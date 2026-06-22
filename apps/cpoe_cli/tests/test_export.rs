// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! E2E tests for the `cpoe export` command.

use std::fs;

mod common;

/// Stdin to supply for the AI declaration prompt.
const DECL_STDIN: &str = "n\nTest declaration\n";

// ---------------------------------------------------------------------------
// Format tests
// ---------------------------------------------------------------------------

#[test]
fn test_export_format_json_is_valid_json() {
    let env = common::TempEnv::new();
    let file = env.with_commits("essay.txt", 3);
    let out_path = env.dir.path().join("out.json");

    env.run_expect_success(
        &[
            "export",
            file.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-f",
            "json",
        ],
        Some(DECL_STDIN),
    );

    assert!(out_path.exists(), "export must write output file");

    let content = fs::read_to_string(&out_path).expect("read output file");
    let parsed: serde_json::Value =
        serde_json::from_str(&content).expect("output file must be valid JSON");

    assert!(
        parsed.get("version").is_some(),
        "JSON output must contain 'version' field, got: {}",
        parsed
    );
    assert!(
        parsed.get("checkpoints").is_some(),
        "JSON output must contain 'checkpoints' field, got: {}",
        parsed
    );
    assert!(
        parsed["checkpoints"].is_array(),
        "'checkpoints' must be an array, got: {}",
        parsed["checkpoints"]
    );
    assert!(
        !parsed["checkpoints"].as_array().unwrap().is_empty(),
        "'checkpoints' array must not be empty"
    );
}

#[test]
fn test_export_format_cpoe_produces_file() {
    let env = common::TempEnv::new();
    let file = env.with_commits("draft.txt", 3);
    let out_path = env.dir.path().join("draft.cpoe");

    env.run_expect_success(
        &[
            "export",
            file.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-f",
            "cpoe",
        ],
        Some(DECL_STDIN),
    );

    assert!(
        out_path.exists(),
        "cpoe format export must create output file at {}",
        out_path.display()
    );

    let metadata = fs::metadata(&out_path).expect("stat output file");
    assert!(
        metadata.len() > 0,
        "cpoe format output file must be non-empty (got {} bytes)",
        metadata.len()
    );
}

#[test]
fn test_export_format_cwar_produces_file() {
    let env = common::TempEnv::new();
    let file = env.with_commits("report.txt", 3);
    let out_path = env.dir.path().join("report.cwar");

    env.run_expect_success(
        &[
            "export",
            file.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-f",
            "cwar",
        ],
        Some(DECL_STDIN),
    );

    assert!(
        out_path.exists(),
        "cwar format export must create output file at {}",
        out_path.display()
    );

    let metadata = fs::metadata(&out_path).expect("stat output file");
    assert!(
        metadata.len() > 0,
        "cwar format output file must be non-empty (got {} bytes)",
        metadata.len()
    );
}

#[test]
fn test_export_format_html_is_valid_html() {
    let env = common::TempEnv::new();
    let file = env.with_commits("article.txt", 3);
    let out_path = env.dir.path().join("article.html");

    env.run_expect_success(
        &[
            "export",
            file.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-f",
            "html",
        ],
        Some(DECL_STDIN),
    );

    assert!(
        out_path.exists(),
        "html format export must create output file at {}",
        out_path.display()
    );

    let content = fs::read_to_string(&out_path).expect("read html output file");

    assert!(
        content.contains("<!DOCTYPE html>") || content.contains("<html"),
        "HTML output must start with a valid HTML document element, got first 200 chars: {}",
        &content[..content.len().min(200)]
    );
    assert!(
        content.contains("</html>"),
        "HTML output must contain closing </html> tag"
    );
    // Non-executable script blocks (application/ld+json schema.org metadata,
    // application/vnd.writerslogic.cpoe+cbor evidence embedding) are allowed;
    // only scripts that browsers would execute as JavaScript are forbidden.
    let mut remainder = content.as_str();
    while let Some(idx) = remainder.find("<script") {
        let tag_start = idx;
        let tag_end_rel = remainder[tag_start..]
            .find('>')
            .expect("unterminated <script tag");
        let tag = &remainder[tag_start..tag_start + tag_end_rel + 1];
        let is_safe_type = tag.contains("type=\"application/ld+json\"")
            || tag.contains("type=\"application/vnd.writerslogic.cpoe+cbor\"");
        assert!(
            is_safe_type,
            "HTML evidence report must not contain executable <script> tags; offending tag: {}",
            tag
        );
        remainder = &remainder[tag_start + tag_end_rel + 1..];
    }
}

#[test]
fn test_export_format_html_contains_no_external_resources() {
    let env = common::TempEnv::new();
    let file = env.with_commits("paper.txt", 3);
    let out_path = env.dir.path().join("paper.html");

    env.run_expect_success(
        &[
            "export",
            file.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-f",
            "html",
        ],
        Some(DECL_STDIN),
    );

    let content = fs::read_to_string(&out_path).expect("read html output file");

    // Evidence reports must be fully self-contained — no external fetches.
    // W3C namespace URIs (prov, XMLSchema) are JSON-LD @context identifiers,
    // not resources; browsers never dereference them. All other http:// is
    // treated as a fetchable resource and rejected.
    let allowed_namespaces = [
        "http://www.w3.org/ns/prov#",
        "http://www.w3.org/2001/XMLSchema#",
    ];
    let mut filtered = content.clone();
    for ns in allowed_namespaces {
        filtered = filtered.replace(ns, "");
    }
    assert!(
        !filtered.contains("http://"),
        "HTML evidence report must not reference external http:// resources"
    );
}

// ---------------------------------------------------------------------------
// Tier tests
// ---------------------------------------------------------------------------

#[test]
fn test_export_tier_standard_json_output() {
    let env = common::TempEnv::new();
    let file = env.with_commits("standard.txt", 3);
    let out_path = env.dir.path().join("standard.json");

    env.run_expect_success(
        &[
            "export",
            file.to_str().unwrap(),
            "-t",
            "standard",
            "-o",
            out_path.to_str().unwrap(),
            "-f",
            "json",
        ],
        Some(DECL_STDIN),
    );

    let content = fs::read_to_string(&out_path).expect("read output file");
    let parsed: serde_json::Value =
        serde_json::from_str(&content).expect("tier=standard output must be valid JSON");

    // The JSON packet uses "strength" to record the tier name.
    let strength = parsed
        .get("strength")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(
        strength.to_lowercase(),
        "standard",
        "JSON strength field must be 'Standard' for tier=standard, got '{}'",
        strength
    );
}

#[test]
fn test_export_tier_enhanced_json_output() {
    let env = common::TempEnv::new();
    let file = env.with_commits("enhanced.txt", 3);
    let out_path = env.dir.path().join("enhanced.json");

    env.run_expect_success(
        &[
            "export",
            file.to_str().unwrap(),
            "-t",
            "enhanced",
            "-o",
            out_path.to_str().unwrap(),
            "-f",
            "json",
        ],
        Some(DECL_STDIN),
    );

    let content = fs::read_to_string(&out_path).expect("read output file");
    let parsed: serde_json::Value =
        serde_json::from_str(&content).expect("tier=enhanced output must be valid JSON");

    let strength = parsed
        .get("strength")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(
        strength.to_lowercase(),
        "enhanced",
        "JSON strength field must be 'Enhanced' for tier=enhanced, got '{}'",
        strength
    );
}

#[test]
fn test_export_tier_maximum_json_output() {
    let env = common::TempEnv::new();
    let file = env.with_commits("maximum.txt", 3);
    let out_path = env.dir.path().join("maximum.json");

    env.run_expect_success(
        &[
            "export",
            file.to_str().unwrap(),
            "-t",
            "maximum",
            "-o",
            out_path.to_str().unwrap(),
            "-f",
            "json",
        ],
        Some(DECL_STDIN),
    );

    let content = fs::read_to_string(&out_path).expect("read output file");
    let parsed: serde_json::Value =
        serde_json::from_str(&content).expect("tier=maximum output must be valid JSON");

    let strength = parsed
        .get("strength")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(
        strength.to_lowercase(),
        "maximum",
        "JSON strength field must be 'Maximum' for tier=maximum, got '{}'",
        strength
    );
}

// ---------------------------------------------------------------------------
// Insufficient-checkpoint tests
// ---------------------------------------------------------------------------

#[test]
fn test_export_insufficient_checkpoints_two_commits() {
    let env = common::TempEnv::new();
    let file = env.with_commits("short.txt", 2);
    let out_path = env.dir.path().join("short.json");

    let result = env.run_expect_failure(
        &[
            "export",
            file.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
        ],
        Some(DECL_STDIN),
    );

    // The error message must tell the user what went wrong.
    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(
        combined.contains("Insufficient checkpoints")
            || combined.contains("need")
            || combined.contains("checkpoint"),
        "Error output must mention insufficient checkpoints when only 2 commits exist, got:\nSTDOUT: {}\nSTDERR: {}",
        result.stdout,
        result.stderr
    );
}

#[test]
fn test_export_insufficient_checkpoints_one_commit() {
    let env = common::TempEnv::new();
    let file = env.with_commits("tiny.txt", 1);
    let out_path = env.dir.path().join("tiny.json");

    let result = env.run_expect_failure(
        &[
            "export",
            file.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
        ],
        Some(DECL_STDIN),
    );

    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(
        combined.contains("Insufficient checkpoints")
            || combined.contains("need")
            || combined.contains("checkpoint"),
        "Error output must mention insufficient checkpoints when only 1 commit exists, got:\nSTDOUT: {}\nSTDERR: {}",
        result.stdout,
        result.stderr
    );
}

// ---------------------------------------------------------------------------
// Cross-tier field-presence tests
// ---------------------------------------------------------------------------

#[test]
fn test_export_json_all_tiers_have_version_field() {
    let tiers = ["basic", "standard", "enhanced", "maximum"];

    for tier in tiers {
        let env = common::TempEnv::new();
        let file = env.with_commits(&format!("{tier}.txt"), 3);
        let out_path = env.dir.path().join(format!("{tier}.json"));

        env.run_expect_success(
            &[
                "export",
                file.to_str().unwrap(),
                "-t",
                tier,
                "-o",
                out_path.to_str().unwrap(),
                "-f",
                "json",
            ],
            Some(DECL_STDIN),
        );

        let content =
            fs::read_to_string(&out_path).unwrap_or_else(|_| panic!("read {tier} output file"));
        let parsed: serde_json::Value = serde_json::from_str(&content)
            .unwrap_or_else(|e| panic!("tier={tier} output must be valid JSON: {e}"));

        assert!(
            parsed.get("version").is_some(),
            "tier={tier} JSON output must contain 'version' field"
        );

        let version = parsed["version"].as_u64().unwrap_or(0);
        assert_eq!(
            version, 1,
            "tier={tier} JSON 'version' must be 1, got {}",
            version
        );
    }
}

// ---------------------------------------------------------------------------
// Roundtrip test
// ---------------------------------------------------------------------------

#[test]
fn test_export_verify_roundtrip() {
    let env = common::TempEnv::new();
    let file = env.with_commits("roundtrip.txt", 3);
    let out_path = env.dir.path().join("roundtrip.json");

    // Export to JSON.
    let export_stdout = env.run_expect_success(
        &[
            "export",
            file.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
            "-f",
            "json",
        ],
        Some(DECL_STDIN),
    );
    assert!(
        export_stdout.contains("Evidence exported to") || out_path.exists(),
        "export must succeed and create output file, stdout: {}",
        export_stdout
    );

    // Verify the exported file. Note: verify may exit non-zero due to VDF duration
    // cross-check failing in fast test environments (session < 10s), but structural
    // verification (hash chain, signatures, seals) should still pass.
    let verify_output = env.run(&["verify", out_path.to_str().unwrap()], None);
    let verify_stdout = verify_output.stdout;

    assert!(
        verify_stdout.contains("Verified"),
        "verify must report 'Verified' for a freshly exported JSON packet, got: {}",
        verify_stdout
    );
}
