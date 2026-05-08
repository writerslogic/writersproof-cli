// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! `cpoe attest` — one-shot text attestation via ephemeral sessions.

use anyhow::{anyhow, Result};
use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;

use cpoe::ffi;

use crate::output::OutputMode;

pub(crate) fn cmd_attest(
    format: &str,
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    non_interactive: bool,
    out: &OutputMode,
) -> Result<()> {
    let init = ffi::ffi_init();
    if !init.success {
        return Err(anyhow!("init: {}", init.error_message.unwrap_or_default()));
    }

    // Piped stdin consumes all input; declaration prompts will reach EOF.
    let from_stdin = input.is_none();
    let content = if let Some(path) = &input {
        std::fs::read_to_string(path).map_err(|e| anyhow!("read input: {e}"))?
    } else {
        let mut buf = String::new();
        if io::stdin().is_terminal() && !non_interactive && !out.quiet {
            eprintln!("Enter text to attest (Ctrl-D to finish):");
        }
        io::stdin()
            .take(50_000_000)
            .read_to_string(&mut buf)
            .map_err(|e| anyhow!("read stdin: {e}"))?;
        buf
    };

    if content.trim().is_empty() {
        return Err(anyhow!(
            "No content to attest. Provide --input <file> or pipe content to stdin."
        ));
    }

    let context_label = input
        .as_ref()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("stdin")
        .to_string();

    let start = ffi::ffi_start_ephemeral_session(context_label);
    if !start.success {
        return Err(anyhow!(
            "ephemeral session: {}",
            start.error_message.unwrap_or_default()
        ));
    }
    let session_id = start.session_id;

    let cp = ffi::ffi_ephemeral_checkpoint(
        session_id.clone(),
        content.clone(),
        "CLI attest".to_string(),
    );
    if !cp.success {
        return Err(anyhow!(
            "Checkpoint failed: {}",
            cp.error_message.unwrap_or_default()
        ));
    }

    let statement = if non_interactive || from_stdin {
        "I authored this text.".to_string()
    } else {
        eprint!("Declaration statement (or press Enter for default): ");
        io::stderr().flush()?;
        let mut stmt = String::new();
        io::stdin().read_line(&mut stmt)?;
        let trimmed = stmt.trim().to_string();
        if trimmed.is_empty() {
            "I authored this text.".to_string()
        } else {
            trimmed
        }
    };

    let result = ffi::ffi_ephemeral_finalize(session_id, content, statement);
    if !result.success {
        return Err(anyhow!(
            "finalize: {}",
            result.error_message.unwrap_or_default()
        ));
    }

    let format_lower = format.to_lowercase();
    let proof = match format_lower.as_str() {
        "json" => serde_json::json!({
            "war_block": result.war_block,
            "compact_ref": result.compact_ref,
        })
        .to_string(),
        "compact" => result.compact_ref.clone(),
        "both" => format!("{}\n{}", result.war_block, result.compact_ref),
        _ => result.war_block.clone(),
    };

    if let Some(out_path) = output {
        std::fs::write(&out_path, &proof).map_err(|e| anyhow!("write output: {e}"))?;
        if !out.quiet {
            eprintln!("Proof written to: {}", out_path.display());
        }
    } else {
        io::stdout().write_all(proof.as_bytes())?;
        if !proof.ends_with('\n') {
            io::stdout().write_all(b"\n")?;
        }
    }

    if !out.quiet && format_lower != "compact" && format_lower != "json" {
        eprintln!("Compact ref: {}", result.compact_ref);
    }

    Ok(())
}
