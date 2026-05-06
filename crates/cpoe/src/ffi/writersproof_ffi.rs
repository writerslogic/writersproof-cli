// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use crate::ffi::helpers::{load_api_key, load_did, load_events_for_path, load_signing_key, open_store};
use crate::ffi::types::{catch_ffi_panic, try_ffi, FfiResult};

/// Anchor a document's latest checkpoint to the WritersProof transparency log.
///
/// Uses the latest event_hash from the store (matching CLI behavior), signs
/// the raw hash bytes with Ed25519, and submits to the WritersProof API.
/// Requires a valid API key stored at `~/Library/Application Support/WritersProof/writersproof_api_key`.
///
/// Note: Function named with underscore in `writers_proof` so UniFFI generates
/// `ffiAnchorToWritersProof` (capital P) matching the Swift call site.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_anchor_to_writers_proof(document_path: String) -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    if document_path.len() > 4096 {
        return FfiResult::err("Document path too long".to_string());
    }
    // Load events from store to get the latest event_hash (matches CLI behavior)
    let (doc_path_str, _store, events) =
        try_ffi!(load_events_for_path(&document_path), FfiResult);
    let latest = match events.last() {
        Some(ev) => ev,
        None => {
            return FfiResult::err("No checkpoints found for this document".to_string());
        }
    };

    if latest.content_hash.len() != 32 || latest.event_hash.len() != 32 {
        return FfiResult::err("Corrupt checkpoint: invalid hash length".to_string());
    }

    // EH-011: evidence_hash must bind to document content, not duplicate event_hash.
    let evidence_hash = hex::encode(latest.content_hash);

    // Load signing key and sign the raw hash bytes (matches CLI: signing_key.sign(latest.event_hash.as_slice()))
    let signing_key = try_ffi!(load_signing_key(), FfiResult);
    let signature = {
        use ed25519_dalek::Signer;
        const DST: &[u8] = b"witnessd-anchor-v1";
        let mut payload = Vec::with_capacity(DST.len() + latest.event_hash.len());
        payload.extend_from_slice(DST);
        payload.extend_from_slice(latest.event_hash.as_slice());
        hex::encode(signing_key.sign(&payload).to_bytes())
    };
    drop(signing_key);

    let did = try_ffi!(
        load_did().map_err(|e| format!("DID identity required for anchor: {e}")),
        FfiResult
    );
    let api_key = match load_api_key() {
        Ok(k) if k.is_empty() => {
            return FfiResult::err("WritersProof API key is empty".to_string());
        }
        Ok(k) => k,
        Err(e) => {
            return FfiResult::err(format!("WritersProof API key not configured. {e}"));
        }
    };

    let doc_name = std::path::Path::new(&doc_path_str)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string());

    let rt = match crate::ffi::beacon::beacon_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            return FfiResult::err(format!("Failed to get async runtime: {e}"));
        }
    };

    let client = match crate::writersproof::WritersProofClient::new(
        crate::writersproof::client::DEFAULT_API_URL,
    ) {
        Ok(c) => c.with_jwt(api_key),
        Err(e) => {
            return FfiResult::err(format!("Failed to create API client: {e}"));
        }
    };

    let result = rt.block_on(async {
        use crate::writersproof::{AnchorMetadata, AnchorRequest};

        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            client.anchor(AnchorRequest {
                evidence_hash,
                author_did: did,
                signature,
                metadata: Some(AnchorMetadata {
                    document_name: doc_name,
                    tier: Some("anchored".into()),
                }),
            }),
        )
        .await
    });

    match result {
        Err(_) => FfiResult::err("Anchor request timed out after 30s".to_string()),
        Ok(Err(e)) => FfiResult::err(format!("Anchor request failed: {e}")),
        Ok(Ok(resp)) => FfiResult::ok(format!(
            "Anchored: {} (log index {})",
            resp.anchor_id, resp.log_index
        )),
    }
    })
}

#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_publish_evidence(
    document_path: String,
    attestation: String,
    ai_declaration: Option<String>,
) -> crate::ffi::types::FfiPublishResult {
    use crate::ffi::types::{FfiErrResult, FfiPublishResult};
    catch_ffi_panic!(FfiPublishResult::ffi_err("engine internal error"), {

    const MAX_ATTESTATION_LEN: usize = 1_000_000;
    if attestation.is_empty() {
        return FfiPublishResult::ffi_err("Author attestation is required to publish");
    }
    if attestation.len() > MAX_ATTESTATION_LEN {
        return FfiPublishResult::ffi_err(format!(
            "Attestation too large: {} bytes (max {MAX_ATTESTATION_LEN})",
            attestation.len()
        ));
    }
    if let Some(ref decl) = ai_declaration {
        if decl.len() > MAX_ATTESTATION_LEN {
            return FfiPublishResult::ffi_err(format!(
                "AI declaration too large: {} bytes (max {MAX_ATTESTATION_LEN})",
                decl.len()
            ));
        }
    }

    if document_path.len() > 4096 {
        return FfiPublishResult::ffi_err("Document path too long");
    }
    let doc_path = try_ffi!(
        crate::sentinel::helpers::validate_path(&document_path)
            .map_err(|e| format!("Invalid document path: {e}")),
        FfiPublishResult
    );
    let doc_path = try_ffi!(
        doc_path
            .canonicalize()
            .map_err(|e| format!("Cannot resolve document path: {e}")),
        FfiPublishResult
    );
    let doc_path_str = doc_path.to_string_lossy().into_owned();

    // Flush a final checkpoint to capture the latest document state.
    if let Some(sentinel) = crate::ffi::sentinel::get_sentinel() {
        if !sentinel.commit_checkpoint_for_path(&doc_path_str) {
            log::warn!("final checkpoint flush failed; publishing with existing data");
        }
    }

    let store = try_ffi!(open_store(), FfiPublishResult);
    let events = try_ffi!(
        store
            .get_events_for_file(&doc_path_str)
            .map_err(|e| format!("Failed to load events: {e}")),
        FfiPublishResult
    );
    let latest = match events.last() {
        Some(ev) => ev,
        None => return FfiPublishResult::ffi_err("No checkpoints found for this document"),
    };
    let checkpoint_count = events.len() as u64;

    if checkpoint_count < 2 {
        return FfiPublishResult::ffi_err("At least 2 checkpoints are required before publishing");
    }

    if latest.content_hash.len() != 32 || latest.event_hash.len() != 32 {
        return FfiPublishResult::ffi_err("Corrupt checkpoint: invalid hash length");
    }

    // Verify chain integrity: each event's previous_hash must match prior event_hash.
    let chain_valid = events
        .windows(2)
        .all(|w| w[1].previous_hash == w[0].event_hash);
    if !chain_valid {
        return FfiPublishResult {
            success: false,
            canonical_url: None,
            record_id: None,
            verification_passed: false,
            checkpoint_count,
            error_message: Some(
                "Evidence chain verification failed. Cannot publish tampered evidence.".to_string(),
            ),
        };
    }

    let evidence_hash = hex::encode(latest.content_hash);

    let signing_key = try_ffi!(load_signing_key(), FfiPublishResult);
    let signature = {
        use ed25519_dalek::Signer;
        const DST: &[u8] = b"witnessd-publish-v1";
        let mut payload = Vec::with_capacity(DST.len() + latest.event_hash.len());
        payload.extend_from_slice(DST);
        payload.extend_from_slice(latest.event_hash.as_slice());
        hex::encode(signing_key.sign(&payload).to_bytes())
    };
    drop(signing_key);

    let did = try_ffi!(
        load_did().map_err(|e| format!("Author identity required to publish. {e}")),
        FfiPublishResult
    );
    let api_key = try_ffi!(
        load_api_key().map_err(|e| format!("WritersProof account required to publish. {e}")),
        FfiPublishResult
    );

    let doc_name = doc_path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string());

    let rt = try_ffi!(
        crate::ffi::beacon::beacon_runtime()
            .map_err(|e| format!("Failed to get async runtime: {e}")),
        FfiPublishResult
    );

    let client = try_ffi!(
        crate::writersproof::WritersProofClient::new(crate::writersproof::client::DEFAULT_API_URL)
            .map_err(|e| format!("Failed to create API client: {e}")),
        FfiPublishResult
    )
    .with_jwt(api_key);

    let result = rt.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            client.publish(crate::writersproof::types::PublishRequest {
                evidence_hash,
                author_did: did,
                signature,
                attestation,
                checkpoint_count,
                document_name: doc_name,
                ai_declaration,
            }),
        )
        .await
    });

    match result {
        Err(_) => FfiPublishResult::ffi_err("Publish request timed out after 30s"),
        Ok(Err(e)) => FfiPublishResult::ffi_err(format!("Publish failed: {e}")),
        Ok(Ok(resp)) => FfiPublishResult {
            success: true,
            canonical_url: Some(resp.canonical_url),
            record_id: Some(resp.record_id),
            verification_passed: true,
            checkpoint_count,
            error_message: None,
        },
    }
    })
}

/// Sync a text attestation to the WritersProof API for public verification.
///
/// Called after `ffi_attest_text` stores the attestation locally. Submits the
/// hash, tier, and signature so verifiers can look it up at
/// `verify.writersproof.com`.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_sync_text_attestation(
    content_hash: String,
    tier: String,
    writersproof_id: String,
    attested_at: String,
    app_bundle_id: String,
) -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    if content_hash.len() != 64 || !content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return FfiResult::err("content_hash must be 64 hex characters".to_string());
    }
    if !(writersproof_id.len() == 8 || writersproof_id.len() == 16) {
        return FfiResult::err("writersproof_id must be 8 or 16 hex characters".to_string());
    }

    let signing_key = try_ffi!(
        load_signing_key().map_err(|e| format!("Signing key unavailable: {e}")),
        FfiResult
    );

    let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());

    // Sign with domain separation: DST || content_hash_bytes.
    let signature_hex = {
        use ed25519_dalek::Signer;
        const DST: &[u8] = b"witnessd-text-attest-v1";
        let hash_bytes = try_ffi!(
            hex::decode(&content_hash).map_err(|e| format!("Invalid content_hash hex: {e}")),
            FfiResult
        );
        let mut payload = Vec::with_capacity(DST.len() + hash_bytes.len());
        payload.extend_from_slice(DST);
        payload.extend_from_slice(&hash_bytes);
        hex::encode(signing_key.sign(&payload).to_bytes())
    };
    drop(signing_key);

    let api_key = match load_api_key() {
        Ok(k) if k.is_empty() => {
            return FfiResult::err("WritersProof API key is empty".to_string());
        }
        Ok(k) => k,
        Err(_) => {
            // No API key — skip sync silently (offline/unauthenticated mode).
            return FfiResult::ok("Skipped: no API key configured".to_string());
        }
    };

    let rt = try_ffi!(
        crate::ffi::beacon::beacon_runtime()
            .map_err(|e| format!("Failed to get async runtime: {e}")),
        FfiResult
    );
    let client = try_ffi!(
        crate::writersproof::WritersProofClient::new(crate::writersproof::client::DEFAULT_API_URL)
            .map_err(|e| format!("Failed to create API client: {e}")),
        FfiResult
    )
    .with_jwt(api_key);

    let anchor_evidence_hash = content_hash.clone();
    let anchor_tier = tier.clone();

    let req = crate::writersproof::types::TextAttestationRequest {
        content_hash,
        tier,
        writersproof_id: writersproof_id.clone(),
        signature_hex,
        public_key_hex,
        attested_at,
        app_bundle_id: Some(app_bundle_id).filter(|s| !s.is_empty()),
        device_id: None,
    };
    let queue_req = req.clone();

    let result = rt.block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            client.submit_text_attestation(req),
        )
        .await
    });

    match result {
        Err(_) | Ok(Err(_)) => {
            let err_msg = match &result {
                Err(_) => "timeout".to_string(),
                Ok(Err(e)) => e.to_string(),
                _ => unreachable!(),
            };
            match crate::writersproof::OfflineQueue::default_dir()
                .and_then(|d| crate::writersproof::OfflineQueue::new(&d))
                .and_then(|q| q.enqueue_text_attestation(queue_req))
            {
                Ok(id) => {
                    log::info!("Text attestation queued for retry: {id} ({err_msg})");
                    FfiResult::ok(format!("Queued for retry: {writersproof_id}"))
                }
                Err(qe) => {
                    log::warn!("Failed to queue text attestation: {qe}");
                    FfiResult::err(format!(
                        "Sync failed ({err_msg}) and queuing failed: {qe}"
                    ))
                }
            }
        }
        Ok(Ok(_)) => {
            // Re-sign with anchor-specific DST for transparency log.
            let anchor_sig = match load_signing_key() {
                Ok(k) => {
                    use ed25519_dalek::Signer;
                    const DST: &[u8] = b"witnessd-anchor-v1";
                    let hash_bytes = hex::decode(&anchor_evidence_hash).unwrap_or_default();
                    let mut payload = Vec::with_capacity(DST.len() + hash_bytes.len());
                    payload.extend_from_slice(DST);
                    payload.extend_from_slice(&hash_bytes);
                    let sig = hex::encode(k.sign(&payload).to_bytes());
                    drop(k);
                    sig
                }
                Err(e) => {
                    log::warn!("Cannot sign anchor: {e}");
                    return FfiResult::ok(format!("Synced (anchor skipped): {writersproof_id}"));
                }
            };
            let anchor_req = crate::writersproof::AnchorRequest {
                evidence_hash: anchor_evidence_hash.clone(),
                author_did: String::new(),
                signature: anchor_sig.clone(),
                metadata: Some(crate::writersproof::AnchorMetadata {
                    document_name: None,
                    tier: Some(anchor_tier.clone()),
                }),
            };
            let anchor_result = rt.block_on(async {
                tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    client.anchor(anchor_req),
                )
                .await
            });
            match anchor_result {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    log::warn!("Post-attestation anchor failed, queuing for retry: {e}");
                    if let Err(qe) = crate::writersproof::OfflineQueue::default_dir()
                        .and_then(|d| crate::writersproof::OfflineQueue::new(&d))
                        .and_then(|q| {
                            q.enqueue_anchor(
                                anchor_evidence_hash.clone(),
                                anchor_sig.clone(),
                                Some(anchor_tier.clone()),
                            )
                        })
                    {
                        log::warn!("Failed to queue anchor for retry: {qe}");
                    }
                }
                Err(_) => {
                    log::warn!("Post-attestation anchor timed out, queuing for retry");
                    if let Err(qe) = crate::writersproof::OfflineQueue::default_dir()
                        .and_then(|d| crate::writersproof::OfflineQueue::new(&d))
                        .and_then(|q| {
                            q.enqueue_anchor(
                                anchor_evidence_hash.clone(),
                                anchor_sig.clone(),
                                Some(anchor_tier.clone()),
                            )
                        })
                    {
                        log::warn!("Failed to queue anchor for retry: {qe}");
                    }
                }
            }
            FfiResult::ok(format!("Synced: {writersproof_id}"))
        }
    }
    })
}

/// Drain all queued text attestations, submitting them to the WritersProof API.
///
/// Call on app launch, after sign-in, or when network connectivity is restored.
/// Returns the number of successful submissions.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_drain_text_attestation_queue() -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    let api_key = match load_api_key() {
        Ok(k) if k.is_empty() => {
            return FfiResult::err("Not authenticated".to_string());
        }
        Ok(k) => k,
        Err(_) => return FfiResult::ok("No API key; nothing to drain".to_string()),
    };

    let queue = match crate::writersproof::OfflineQueue::default_dir()
        .and_then(|d| crate::writersproof::OfflineQueue::new(&d))
    {
        Ok(q) => q,
        Err(e) => return FfiResult::err(format!("Cannot open queue: {e}")),
    };

    let text_count = match queue.text_attestation_count() {
        Ok(n) => n,
        Err(e) => return FfiResult::err(format!("Cannot read queue: {e}")),
    };
    let anchor_count = queue.list_anchors().map(|v| v.len()).unwrap_or(0);

    if text_count == 0 && anchor_count == 0 {
        return FfiResult::ok("Queue empty".to_string());
    }

    let rt = match crate::ffi::beacon::beacon_runtime() {
        Ok(rt) => rt,
        Err(e) => return FfiResult::err(format!("No async runtime: {e}")),
    };

    let client = match crate::writersproof::WritersProofClient::new(
        crate::writersproof::client::DEFAULT_API_URL,
    ) {
        Ok(c) => c.with_jwt(api_key),
        Err(e) => return FfiResult::err(format!("Client error: {e}")),
    };

    let result = rt.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            let text_result = queue.drain_text_attestations(&client).await?;
            let anchor_result = queue.drain_anchors(&client).await?;
            Ok::<_, crate::error::Error>((text_result, anchor_result))
        })
        .await
    });

    match result {
        Err(_) => FfiResult::err("Queue drain timed out".to_string()),
        Ok(Err(e)) => FfiResult::err(format!("Queue drain failed: {e}")),
        Ok(Ok(((text_ok, text_discarded), (anchor_ok, anchor_discarded)))) => {
            let mut parts = Vec::new();
            if text_count > 0 {
                parts.push(format!("Drained {text_ok}/{text_count} text attestations"));
            }
            if anchor_count > 0 {
                parts.push(format!("anchors {anchor_ok}/{anchor_count}"));
            }
            let total_discarded = text_discarded + anchor_discarded;
            if total_discarded > 0 {
                parts.push(format!("discarded {total_discarded}"));
            }
            FfiResult::ok(parts.join(", "))
        }
    }
    })
}
