// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, Context, Result};
use std::path::Path;

use crate::output::OutputMode;

/// Maximum credential file size accepted for rendering (4 MiB). Bounds the read
/// of untrusted input.
const MAX_CREDENTIAL_SIZE: u64 = 4 * 1024 * 1024;

/// Render the canonical authorship badge (SVG) for an Open Badge credential.
///
/// The badge is produced by the engine's deterministic badge-fingerprint core —
/// the same renderer the verify portal uses — so the rendered image matches what
/// a verifier re-derives from the signed credential (render == verify). The
/// authorship mode and assurance tier are read from the credential's achievement;
/// the short-id is derived from the subject DID. Unknown mode/tier values degrade
/// safely in the renderer, so a malformed field cannot inflate the badge.
pub(crate) fn cmd_badge(credential: &Path, output: Option<&Path>, out: &OutputMode) -> Result<()> {
    let meta = std::fs::metadata(credential)
        .with_context(|| format!("cannot stat credential at {}", credential.display()))?;
    if meta.len() > MAX_CREDENTIAL_SIZE {
        return Err(anyhow!(
            "credential file too large: {} bytes (max {})",
            meta.len(),
            MAX_CREDENTIAL_SIZE
        ));
    }

    let data = std::fs::read(credential)
        .with_context(|| format!("cannot read credential at {}", credential.display()))?;
    let root: serde_json::Value =
        serde_json::from_slice(&data).context("credential is not valid JSON")?;

    let subject = root
        .get("credentialSubject")
        .ok_or_else(|| anyhow!("credential has no credentialSubject"))?;
    let did = subject
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("credentialSubject has no id (author DID)"))?;

    let achievement = subject.get("achievement");
    let mode = achievement
        .and_then(|a| a.get("id"))
        .and_then(|v| v.as_str())
        .and_then(|id| id.rsplit('/').next())
        .unwrap_or("human-authored");
    let tier = achievement
        .and_then(|a| a.get("tag"))
        .and_then(|v| v.as_array())
        .and_then(|tags| {
            tags.iter()
                .filter_map(|t| t.as_str())
                .find_map(|t| t.strip_prefix("assurance:"))
        })
        .unwrap_or("declared");

    let svg = cpoe::ffi::badge_render::ffi_render_badge_for_identifier(
        did.to_string(),
        mode.to_string(),
        tier.to_string(),
    );
    if svg.is_empty() {
        return Err(anyhow!("badge rendering produced empty output"));
    }

    match output {
        Some(path) => {
            std::fs::write(path, svg.as_bytes())
                .with_context(|| format!("cannot write badge SVG to {}", path.display()))?;
            if out.json {
                println!(
                    "{}",
                    serde_json::json!({ "success": true, "file": path.to_string_lossy() })
                );
            } else if !out.quiet {
                println!("Badge SVG written to: {}", path.display());
            }
        }
        None => {
            if out.json {
                println!("{}", serde_json::json!({ "success": true, "svg": svg }));
            } else {
                print!("{svg}");
            }
        }
    }

    Ok(())
}
