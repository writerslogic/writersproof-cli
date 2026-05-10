// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Result};
use std::path::PathBuf;

use crate::cli::SnapshotAction;
use crate::output::OutputMode;
use crate::util::{check_ffi_result, path_str};

pub(crate) fn cmd_snapshot(action: SnapshotAction, out: &OutputMode) -> Result<()> {
    match action {
        SnapshotAction::Save { path } => cmd_snapshot_save(&path, out),
        SnapshotAction::List { path } => cmd_snapshot_list(&path, out),
        SnapshotAction::Get { id } => cmd_snapshot_get(id, out),
        SnapshotAction::Diff { id, path } => cmd_snapshot_diff(id, &path, out),
    }
}

fn cmd_snapshot_save(path: &PathBuf, out: &OutputMode) -> Result<()> {
    let path_str = path_str(path);
    let plaintext = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("Failed to read file: {}", e))?;

    let result = cpoe::ffi::snapshot::ffi_snapshot_save(path_str, plaintext);

    check_ffi_result(result.success, &result.error_message)?;

    if out.json {
        println!(
            "{}",
            serde_json::json!({
                "snapshot_id": result.snapshot_id,
                "size_warning": result.size_warning,
            })
        );
        return Ok(());
    }

    if out.quiet {
        return Ok(());
    }

    println!("Snapshot saved (ID: {})", result.snapshot_id);
    if let Some(warning) = &result.size_warning {
        eprintln!("Warning: {}", warning);
    }

    Ok(())
}

fn cmd_snapshot_list(path: &PathBuf, out: &OutputMode) -> Result<()> {
    let path_str = path_str(path);
    let entries = cpoe::ffi::snapshot::ffi_snapshot_list(path_str);

    if out.json {
        let items: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "id": e.id,
                    "document_path": e.document_path,
                    "timestamp_ns": e.timestamp_ns,
                    "word_count": e.word_count,
                    "word_count_delta": e.word_count_delta,
                    "draft_label": e.draft_label,
                    "is_restore": e.is_restore,
                    "session_group": e.session_group,
                })
            })
            .collect();
        println!("{}", serde_json::Value::Array(items));
        return Ok(());
    }

    if entries.is_empty() {
        if !out.quiet {
            println!("No snapshots found for this document.");
        }
        return Ok(());
    }

    if out.quiet {
        return Ok(());
    }

    println!("=== Snapshots ({}) ===", entries.len());
    for entry in &entries {
        let label = entry
            .draft_label
            .as_deref()
            .unwrap_or("");
        let delta = if entry.word_count_delta >= 0 {
            format!("+{}", entry.word_count_delta)
        } else {
            format!("{}", entry.word_count_delta)
        };
        println!(
            "  #{}: {} words ({}) {}{}",
            entry.id,
            entry.word_count,
            delta,
            if entry.is_restore { "[restored] " } else { "" },
            label
        );
    }

    Ok(())
}

fn cmd_snapshot_get(id: i64, out: &OutputMode) -> Result<()> {
    let result = cpoe::ffi::snapshot::ffi_snapshot_get(id);

    check_ffi_result(result.success, &result.error_message)?;

    let text = result.plaintext.unwrap_or_default();

    if out.json {
        println!(
            "{}",
            serde_json::json!({
                "snapshot_id": id,
                "plaintext": text,
            })
        );
    } else {
        print!("{}", text);
    }

    Ok(())
}

fn cmd_snapshot_diff(id: i64, path: &PathBuf, out: &OutputMode) -> Result<()> {
    let current_text = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("Failed to read current file: {}", e))?;

    let ops = cpoe::ffi::snapshot::ffi_snapshot_diff(id, current_text);

    if out.json {
        let items: Vec<serde_json::Value> = ops
            .iter()
            .map(|op| {
                serde_json::json!({
                    "tag": op.tag,
                    "text": op.text,
                })
            })
            .collect();
        println!("{}", serde_json::Value::Array(items));
        return Ok(());
    }

    if ops.is_empty() {
        if !out.quiet {
            println!("No differences found.");
        }
        return Ok(());
    }

    if out.quiet {
        return Ok(());
    }

    for op in &ops {
        match op.tag.as_str() {
            "equal" => print!("{}", op.text),
            "insert" => print!("\x1b[32m{}\x1b[0m", op.text),
            "delete" => print!("\x1b[31m{}\x1b[0m", op.text),
            _ => print!("{}", op.text),
        }
    }
    println!();

    Ok(())
}
