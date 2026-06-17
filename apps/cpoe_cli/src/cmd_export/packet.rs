// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::fs;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::time::Duration;

use anyhow::{anyhow, Result};
use chrono::Utc;

use cpoe::authorproof_protocol::crypto::EvidenceSigner;
use cpoe::authorproof_protocol::rfc::{CBOR_TAG_ATTESTATION_RESULT, CBOR_TAG_EVIDENCE_PACKET};
use cpoe::declaration::{self, AiExtent, AiPurpose, ModalityType};

use crate::output::OutputMode;
use crate::spec::MIN_CHECKPOINTS_PER_PACKET;

use super::CHAR_COUNT_READ_LIMIT;

/// Parameters for evidence packet construction.
pub(super) struct EvidencePacketContext<'a> {
    pub(super) file_path: &'a std::path::Path,
    pub(super) abs_path_str: &'a str,
    pub(super) events: &'a [cpoe::SecureEvent],
    pub(super) latest: &'a cpoe::SecureEvent,
    pub(super) vdf_params: &'a cpoe::vdf::params::Parameters,
    pub(super) tier_lower: &'a str,
    pub(super) spec_content_tier: u8,
    pub(super) spec_profile_uri: &'a str,
    pub(super) spec_attestation_tier: u8,
    pub(super) total_vdf_time: &'a Duration,
    pub(super) decl: &'a declaration::Declaration,
    pub(super) keystroke_evidence: &'a serde_json::Value,
}

pub(super) fn resolve_declaration(
    tier_lower: &str,
    content_hash: [u8; 32],
    chain_hash: [u8; 32],
    title: String,
    signer: &dyn EvidenceSigner,
    out: &OutputMode,
) -> Result<declaration::Declaration> {
    if tier_lower == "basic" {
        if !out.quiet && !out.json {
            eprintln!("Basic tier: using default declaration (no AI tools declared).");
        }
        return declaration::no_ai_declaration(
            content_hash,
            chain_hash,
            &title,
            "Basic-tier evidence: no declaration provided.",
        )
        .sign(signer)
        .map_err(|e| anyhow!("create declaration: {}", e));
    }

    if !std::io::stdin().is_terminal() {
        eprintln!("Non-interactive mode: using default declaration.");
        return declaration::no_ai_declaration(
            content_hash,
            chain_hash,
            &title,
            "Automated export: no interactive declaration collected.",
        )
        .sign(signer)
        .map_err(|e| anyhow!("create declaration: {}", e));
    }

    println!("=== Process Declaration ===");
    println!("You must declare how this document was created.");
    println!();
    collect_declaration(content_hash, chain_hash, title, signer)
}

pub(super) fn build_evidence_packet(ctx: &EvidencePacketContext<'_>) -> Result<serde_json::Value> {
    let EvidencePacketContext {
        file_path,
        abs_path_str,
        events,
        latest,
        vdf_params,
        tier_lower,
        spec_content_tier,
        spec_profile_uri,
        spec_attestation_tier,
        total_vdf_time,
        decl,
        keystroke_evidence,
    } = ctx;

    let strength = match *tier_lower {
        "basic" => "Basic",
        "standard" => "Standard",
        "enhanced" => "Enhanced",
        "maximum" => "Maximum",
        _ => unreachable!("tier validated at entry"),
    };

    // §7.5: CLI commits use SHA-256 VDF (algorithm 10); Argon2id/entangled are
    // selected only by the engine checkpoint chain, which uses SecureEvent fields
    // not available in the flat store model. Using 20/21 here was a spec lie.
    let proof_algorithm: u8 = 10;
    let swf_params = cpoe::vdf::params_for_tier(*spec_content_tier);

    let mut packet_id = [0u8; 16];
    getrandom::getrandom(&mut packet_id)?;

    let checkpoints: Vec<serde_json::Value> = events
        .iter()
        .enumerate()
        .map(|(i, ev)| {
            let elapsed_secs =
                ev.vdf_iterations as f64 / vdf_params.iterations_per_second.max(1) as f64;
            let elapsed_dur = Duration::try_from_secs_f64(elapsed_secs)
                .unwrap_or(Duration::ZERO);
            let elapsed_ms = (elapsed_secs * 1000.0) as u64;

            let mut cp_id = [0u8; 16];
            cp_id.copy_from_slice(&ev.event_hash[..16]);

            serde_json::json!({
                "ordinal": i as u64,
                "sequence": i as u64,
                "checkpoint_id": hex::encode(cp_id),
                "timestamp": chrono::DateTime::from_timestamp_nanos(ev.timestamp_ns).to_rfc3339(),
                "timestamp_ms": (ev.timestamp_ns / 1_000_000).max(0) as u64,
                "content_hash": hex::encode(ev.content_hash),
                "content_size": ev.file_size,
                "char_count": ev.file_size.max(0) as u64,
                "delta": {
                    "chars_added": if ev.size_delta > 0 { ev.size_delta as u64 } else { 0u64 },
                    "chars_deleted": if ev.size_delta < 0 { ev.size_delta.unsigned_abs() as u64 } else { 0u64 },
                    "op_count": 1u64
                },
                "message": ev.context_note.as_deref().or(ev.context_type.as_deref()),
                "vdf_input": ev.vdf_input.map(hex::encode),
                "vdf_output": ev.vdf_output.map(hex::encode),
                "vdf_iterations": ev.vdf_iterations,
                "claimed_duration_ms": elapsed_ms,
                "elapsed_time": {
                    "secs": elapsed_dur.as_secs(),
                    "nanos": elapsed_dur.subsec_nanos()
                },
                "previous_hash": hex::encode(ev.previous_hash),
                "hash": hex::encode(ev.event_hash),
                "process_proof": {
                    "algorithm": proof_algorithm,
                    "params": {
                        "time_cost": swf_params.time_cost,
                        "memory_cost": swf_params.memory_cost,
                        "parallelism": swf_params.parallelism,
                        "iterations": ev.vdf_iterations
                    },
                    "input": ev.vdf_input.map(hex::encode),
                    "claimed_duration_ms": elapsed_ms
                },
                "signature": null
            })
        })
        .collect();

    Ok(serde_json::json!({
        "version": 1,
        "exported_at": Utc::now().to_rfc3339(),
        "strength": strength,

        "spec": {
            "cbor_tag": CBOR_TAG_EVIDENCE_PACKET,
            "war_cbor_tag": CBOR_TAG_ATTESTATION_RESULT,
            "profile_uri": spec_profile_uri,
            "packet_id": hex::encode(packet_id),
            "content_tier": spec_content_tier,
            "attestation_tier": spec_attestation_tier,
            "min_checkpoints": MIN_CHECKPOINTS_PER_PACKET,
            "hash_algorithm": "sha256",
        },

        "provenance": null,
        "document": {
            "title": file_path.file_name().unwrap_or_default().to_string_lossy(),
            "path": abs_path_str,
            "final_hash": hex::encode(latest.content_hash),
            "final_size": latest.file_size,
            "content_hash": {
                "algorithm": 1,
                "digest": hex::encode(latest.content_hash)
            },
            "byte_length": latest.file_size.max(0) as u64,
            "char_count": if latest.file_size > 0 && latest.file_size < CHAR_COUNT_READ_LIMIT {
                fs::read(abs_path_str)
                    .ok()
                    .and_then(|bytes| {
                        // Verify hash matches to ensure we count chars from the same content.
                        use sha2::{Digest, Sha256};
                        let hash: [u8; 32] = Sha256::digest(&bytes).into();
                        if hash != latest.content_hash {
                            return None;
                        }
                        if bytes.len() as u64 > crate::util::MAX_FILE_SIZE {
                            return None;
                        }
                        let text = std::str::from_utf8(&bytes).ok()?;
                        Some(text.chars().count() as u64)
                    })
                    .unwrap_or(latest.file_size.max(0) as u64)
            } else {
                latest.file_size.max(0) as u64
            },
        },
        "checkpoints": checkpoints,
        "vdf_params": {
            "iterations_per_second": vdf_params.iterations_per_second,
            "min_iterations": vdf_params.min_iterations,
            "max_iterations": vdf_params.max_iterations
        },
        "chain_hash": hex::encode(latest.event_hash),
        "chain_length": events.len(),
        "chain_duration_secs": total_vdf_time.as_secs(),
        "declaration": decl,
        "presence": null,
        "hardware": null,
        "keystroke": keystroke_evidence,
        "behavioral": aggregate_semantic_summaries(events),
        "contexts": [],
        "external": null,
        "key_hierarchy": null,
        "claims": [
            {"type": "chain_integrity", "description": "Content states form unbroken cryptographic chain", "confidence": "cryptographic"},
            {"type": "time_elapsed", "description": format!("At least {:?} elapsed during documented composition", total_vdf_time), "confidence": "cryptographic"}
        ],
        "verification_url": "https://writerslogic.com/verify",
        "limitations": [
            "Cannot prove cognitive origin of ideas",
            "Cannot prove absence of AI involvement in ideation"
        ]
    }))
}

#[allow(dead_code)] // Wired once wire-format .cpop export is complete
pub(super) fn build_wire_packet_from_events(
    events: &[cpoe::SecureEvent],
    file_path: &std::path::Path,
    vdf_params: &cpoe::vdf::params::Parameters,
    spec_profile_uri: &str,
    spec_content_tier: u8,
    spec_attestation_tier: u8,
) -> Result<cpoe::EvidencePacketWire> {
    use cpoe::authorproof_protocol::rfc::wire_types::{
        AttestationTier, ContentTier, DocumentRef, EditDelta, HashValue, ProcessProof,
        ProofAlgorithm, ProofParams,
    };

    let latest = events
        .last()
        .ok_or_else(|| anyhow!("No events for CBOR export"))?;

    let filename = file_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string());

    let document = DocumentRef {
        content_hash: HashValue::try_sha256(latest.content_hash.to_vec())
            .map_err(|e| anyhow::anyhow!(e))?,
        filename,
        byte_length: latest.file_size.max(0) as u64,
        char_count: latest.file_size.max(0) as u64,
        salt_mode: None,
        salt_commitment: None,
    };

    let checkpoints: Vec<cpoe::CheckpointWire> = events
        .iter()
        .enumerate()
        .map(|(i, ev)| -> anyhow::Result<cpoe::CheckpointWire> {
            let (input, merkle_root, iterations, claimed_ms) =
                if let (Some(vdf_in), Some(vdf_out)) = (ev.vdf_input, ev.vdf_output) {
                    let ms = if vdf_params.iterations_per_second > 0 {
                        (ev.vdf_iterations as f64 / vdf_params.iterations_per_second as f64
                            * 1000.0) as u64
                    } else {
                        0
                    };
                    (vdf_in.to_vec(), vdf_out.to_vec(), ev.vdf_iterations, ms)
                } else {
                    (vec![0u8; 32], vec![0u8; 32], 0u64, 0u64)
                };

            let process_proof = ProcessProof {
                algorithm: ProofAlgorithm::SwfSha256,
                params: ProofParams {
                    time_cost: 1,
                    memory_cost: 0,
                    parallelism: 1,
                    steps: iterations,
                    waypoint_interval: None,
                    waypoint_memory: None,
                    reads_per_step: None,
                    challenges: None,
                    recursion_depth: None,
                },
                input,
                merkle_root,
                sampled_proofs: vec![],
                claimed_duration: claimed_ms,
            };

            let mut cp_id = [0u8; 16];
            cp_id.copy_from_slice(&ev.event_hash[..16]);

            let mut wire = cpoe::CheckpointWire {
                sequence: i as u64,
                checkpoint_id: cp_id,
                timestamp: (ev.timestamp_ns / 1_000_000).max(0) as u64,
                content_hash: HashValue::try_sha256(ev.content_hash.to_vec())
                    .map_err(|e| anyhow::anyhow!(e))?,
                char_count: ev.file_size.max(0) as u64,
                delta: EditDelta {
                    chars_added: if ev.size_delta > 0 {
                        ev.size_delta as u64
                    } else {
                        0
                    },
                    chars_deleted: if ev.size_delta < 0 {
                        ev.size_delta.unsigned_abs() as u64
                    } else {
                        0
                    },
                    op_count: 1,
                    positions: None,
                    edit_graph_hash: None,
                    cursor_trajectory_histogram: None,
                    revision_depth_histogram: None,
                    pause_duration_histogram: None,
                    metric_binding_hash: None,
                },
                prev_hash: HashValue::try_sha256(ev.previous_hash.to_vec())
                    .map_err(|e| anyhow::anyhow!(e))?,
                checkpoint_hash: HashValue::try_sha256(vec![0u8; 32])
                    .map_err(|e| anyhow::anyhow!(e))?,
                process_proof,
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
                anchors: None,
            };
            wire.checkpoint_hash = wire.compute_hash().map_err(|e| anyhow::anyhow!(e))?;
            Ok(wire)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let mut packet_id = [0u8; 16];
    getrandom::getrandom(&mut packet_id)?;

    Ok(cpoe::EvidencePacketWire {
        version: 1,
        profile_uri: spec_profile_uri.to_string(),
        packet_id,
        created: chrono::Utc::now().timestamp_millis() as u64,
        document,
        checkpoints,
        attestation_tier: Some(match spec_attestation_tier {
            4 => AttestationTier::HardwareHardened,
            3 => AttestationTier::HardwareBound,
            2 => AttestationTier::AttestedSoftware,
            _ => AttestationTier::SoftwareOnly,
        }),
        limitations: None,
        profile: None,
        presence_challenges: None,
        channel_binding: None,
        content_tier: Some(match spec_content_tier {
            3 => ContentTier::Maximum,
            2 => ContentTier::Enhanced,
            _ => ContentTier::Core,
        }),
        signing_public_key: None,
        previous_packet_ref: None,
        packet_sequence: None,
        physical_liveness: None,
        baseline_verification: None,
        author_did: None,
        document_content: None,
        document_filename: None,
        project_files: None,
        session_counter: None,
        forensic_summary: None,
        export_attestation: None,
        document_structure: None,
        continuation_summary: None,
    })
}

/// Aggregate semantic keystroke summaries from checkpoint events into a behavioral section.
///
/// Sums the per-checkpoint `SemanticAccumulator` snapshots to produce totals across
/// the entire evidence chain.
fn aggregate_semantic_summaries(events: &[cpoe::SecureEvent]) -> serde_json::Value {
    let mut characters: u64 = 0;
    let mut delete_backward: u64 = 0;
    let mut delete_forward: u64 = 0;
    let mut delete_word: u64 = 0;
    let mut delete_line: u64 = 0;
    let mut undo: u64 = 0;
    let mut redo: u64 = 0;
    let mut copy: u64 = 0;
    let mut cut: u64 = 0;
    let mut paste: u64 = 0;
    let mut select_all: u64 = 0;
    let mut navigation: u64 = 0;
    let mut find: u64 = 0;
    let mut save: u64 = 0;
    let mut other_shortcut: u64 = 0;
    let mut tab: u64 = 0;
    let mut r#return: u64 = 0;
    let mut found_any = false;

    // Use the last event's semantic summary as the cumulative snapshot,
    // since SemanticAccumulator accumulates over the entire session.
    if let Some(last_summary) = events.iter().rev().find_map(|ev| ev.semantic_summary.as_ref()) {
        if let Ok(acc) = serde_json::from_str::<serde_json::Value>(last_summary) {
            characters = acc.get("characters").and_then(|v| v.as_u64()).unwrap_or(0);
            delete_backward = acc.get("delete_backward").and_then(|v| v.as_u64()).unwrap_or(0);
            delete_forward = acc.get("delete_forward").and_then(|v| v.as_u64()).unwrap_or(0);
            delete_word = acc.get("delete_word").and_then(|v| v.as_u64()).unwrap_or(0);
            delete_line = acc.get("delete_line").and_then(|v| v.as_u64()).unwrap_or(0);
            undo = acc.get("undo").and_then(|v| v.as_u64()).unwrap_or(0);
            redo = acc.get("redo").and_then(|v| v.as_u64()).unwrap_or(0);
            copy = acc.get("copy").and_then(|v| v.as_u64()).unwrap_or(0);
            cut = acc.get("cut").and_then(|v| v.as_u64()).unwrap_or(0);
            paste = acc.get("paste").and_then(|v| v.as_u64()).unwrap_or(0);
            select_all = acc.get("select_all").and_then(|v| v.as_u64()).unwrap_or(0);
            navigation = acc.get("navigation").and_then(|v| v.as_u64()).unwrap_or(0);
            find = acc.get("find").and_then(|v| v.as_u64()).unwrap_or(0);
            save = acc.get("save").and_then(|v| v.as_u64()).unwrap_or(0);
            other_shortcut = acc.get("other_shortcut").and_then(|v| v.as_u64()).unwrap_or(0);
            tab = acc.get("tab").and_then(|v| v.as_u64()).unwrap_or(0);
            r#return = acc.get("return").and_then(|v| v.as_u64()).unwrap_or(0);
            found_any = true;
        }
    }

    if !found_any {
        return serde_json::Value::Null;
    }

    let total_deletions = delete_backward
        .saturating_add(delete_forward)
        .saturating_add(delete_word)
        .saturating_add(delete_line);
    let total = characters
        .saturating_add(total_deletions)
        .saturating_add(undo)
        .saturating_add(redo)
        .saturating_add(copy)
        .saturating_add(cut)
        .saturating_add(paste)
        .saturating_add(select_all)
        .saturating_add(navigation)
        .saturating_add(find)
        .saturating_add(save)
        .saturating_add(other_shortcut)
        .saturating_add(tab)
        .saturating_add(r#return);
    let editing_count = total_deletions
        .saturating_add(undo)
        .saturating_add(redo)
        .saturating_add(cut)
        .saturating_add(paste)
        .saturating_add(select_all);
    let editing_ratio = if total > 0 {
        editing_count as f64 / total as f64
    } else {
        0.0
    };

    serde_json::json!({
        "semantic_keystrokes": {
            "characters": characters,
            "delete_backward": delete_backward,
            "delete_forward": delete_forward,
            "delete_word": delete_word,
            "delete_line": delete_line,
            "undo": undo,
            "redo": redo,
            "copy": copy,
            "cut": cut,
            "paste": paste,
            "select_all": select_all,
            "navigation": navigation,
            "find": find,
            "save": save,
            "other_shortcut": other_shortcut,
            "tab": tab,
            "return": r#return,
            "total": total,
            "total_deletions": total_deletions,
            "editing_ratio": (editing_ratio * 1000.0).round() / 1000.0
        }
    })
}

fn collect_declaration(
    document_hash: [u8; 32],
    chain_hash: [u8; 32],
    title: String,
    signer: &dyn EvidenceSigner,
) -> Result<declaration::Declaration> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();

    println!("Did you use any AI tools in creating this document? (y/n, press Enter for 'no')");
    print!("> ");
    io::stdout().flush()?;

    let mut input = String::new();
    reader.by_ref().take(4096).read_line(&mut input)?;
    let used_ai = crate::util::parse_yes_no(&input) == Some(true);

    println!();
    println!(
        "Enter your declaration statement (press Enter for default: 'I authored this document'):"
    );
    print!("> ");
    io::stdout().flush()?;

    input.clear();
    reader.by_ref().take(4096).read_line(&mut input)?;
    let statement = {
        let trimmed = input.trim().to_string();
        if trimmed.is_empty() {
            "I authored this document".to_string()
        } else {
            trimmed
        }
    };

    let decl = if used_ai {
        println!();
        println!("What AI tool did you use? (e.g., ChatGPT, Claude, Copilot)");
        print!("> ");
        io::stdout().flush()?;

        input.clear();
        reader.by_ref().take(4096).read_line(&mut input)?;
        let tool_name = input.trim().to_string();

        println!();
        println!("What was the extent of AI usage? (minimal/moderate/substantial)");
        print!("> ");
        io::stdout().flush()?;

        input.clear();
        reader.by_ref().take(4096).read_line(&mut input)?;
        let extent_str = input.trim().to_lowercase();
        let extent = match extent_str.as_str() {
            "substantial" => AiExtent::Substantial,
            "moderate" => AiExtent::Moderate,
            _ => AiExtent::Minimal,
        };

        declaration::ai_assisted_declaration(document_hash, chain_hash, &title)
            .add_modality(ModalityType::Keyboard, 100.0, None)
            .add_ai_tool(&tool_name, None, AiPurpose::Drafting, None, extent)
            .with_statement(&statement)
            .sign(signer)
            .map_err(|e| anyhow!("create declaration: {}", e))?
    } else {
        declaration::no_ai_declaration(document_hash, chain_hash, &title, &statement)
            .sign(signer)
            .map_err(|e| anyhow!("create declaration: {}", e))?
    };

    Ok(decl)
}
