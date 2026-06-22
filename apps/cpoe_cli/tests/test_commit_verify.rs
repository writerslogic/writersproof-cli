// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! E2E tests for commit and verify edge cases.

mod common;

use std::fs;

// === Commit: blocked extensions ===

#[test]
fn test_commit_blocked_extension_pdf_rejected() {
    let env = common::TempEnv::with_identity();
    let path = env.create_file("document.pdf", "not actually a PDF");
    let output = env.run_expect_failure(
        &["commit", path.to_str().unwrap(), "-m", "blocked ext"],
        None,
    );
    common::assert_no_panic(&output, "commit PDF");
    let combined = format!("{}{}", output.stdout, output.stderr);
    assert!(
        combined.contains(".pdf") || combined.contains("not a supported"),
        "should mention the blocked extension, got:\nSTDOUT: {}\nSTDERR: {}",
        output.stdout,
        output.stderr,
    );
}

#[test]
fn test_commit_blocked_extension_exe_rejected() {
    let env = common::TempEnv::with_identity();
    let path = env.create_file("program.exe", "not an executable");
    let output = env.run_expect_failure(
        &["commit", path.to_str().unwrap(), "-m", "blocked ext"],
        None,
    );
    common::assert_no_panic(&output, "commit EXE");
}

#[test]
fn test_commit_blocked_extension_zip_rejected() {
    let env = common::TempEnv::with_identity();
    let path = env.create_file("archive.zip", "not a zip");
    let output = env.run_expect_failure(
        &["commit", path.to_str().unwrap(), "-m", "blocked ext"],
        None,
    );
    common::assert_no_panic(&output, "commit ZIP");
}

#[test]
fn test_commit_allowed_extension_txt_accepted() {
    let env = common::TempEnv::with_identity();
    let path = env.create_file("document.txt", "Hello, world!");
    let stdout = env.run_expect_success(
        &["commit", path.to_str().unwrap(), "-m", "allowed ext"],
        None,
    );
    assert!(
        stdout.contains("Checkpoint"),
        "txt file should be accepted, got: {stdout}"
    );
}

#[test]
fn test_commit_allowed_extension_md_accepted() {
    let env = common::TempEnv::with_identity();
    let path = env.create_file("notes.md", "# Markdown content");
    let stdout =
        env.run_expect_success(&["commit", path.to_str().unwrap(), "-m", "markdown"], None);
    assert!(
        stdout.contains("Checkpoint"),
        "md file should be accepted, got: {stdout}"
    );
}

#[test]
fn test_commit_no_extension_accepted() {
    let env = common::TempEnv::with_identity();
    let path = env.create_file("Makefile", "all: build");
    let stdout = env.run_expect_success(&["commit", path.to_str().unwrap(), "-m", "no ext"], None);
    assert!(
        stdout.contains("Checkpoint"),
        "file without extension should be accepted"
    );
}

// === Commit: empty file ===

#[test]
fn test_commit_empty_file_warns_but_succeeds() {
    let env = common::TempEnv::with_identity();
    let path = env.create_file("empty.txt", "");
    let output = env.run(&["commit", path.to_str().unwrap(), "-m", "empty"], None);
    common::assert_no_panic(&output, "commit empty file");
    // Should succeed with a warning about empty file
    assert!(
        output.success,
        "empty file commit should succeed, stderr: {}",
        output.stderr
    );
}

// === Commit: JSON output ===

#[test]
fn test_commit_json_output_has_required_fields() {
    let env = common::TempEnv::with_identity();
    let path = env.create_file("json_test.txt", "JSON output test content");
    let output = env.run(
        &[
            "commit",
            path.to_str().unwrap(),
            "-m",
            "json test",
            "--json",
        ],
        None,
    );
    common::assert_exit_success(&output, "commit --json");
    let json = common::assert_json_valid(&output, "commit --json");
    assert!(
        json.get("checkpoint").is_some(),
        "JSON output should have 'checkpoint' field"
    );
    assert!(
        json.get("content_hash").is_some(),
        "JSON output should have 'content_hash' field"
    );
    assert!(
        json.get("event_hash").is_some(),
        "JSON output should have 'event_hash' field"
    );
    assert!(
        json.get("file_size").is_some(),
        "JSON output should have 'file_size' field"
    );
    assert!(
        json.get("vdf_iterations").is_some(),
        "JSON output should have 'vdf_iterations' field"
    );
}

#[test]
fn test_commit_json_content_hash_is_64_hex() {
    let env = common::TempEnv::with_identity();
    let path = env.create_file("hash_test.txt", "hash validation test");
    let output = env.run(
        &[
            "commit",
            path.to_str().unwrap(),
            "-m",
            "hash check",
            "--json",
        ],
        None,
    );
    common::assert_exit_success(&output, "commit --json hash check");
    let json = common::assert_json_valid(&output, "commit hash");
    let hash = json["content_hash"]
        .as_str()
        .expect("content_hash should be string");
    assert_eq!(
        hash.len(),
        64,
        "content_hash should be 64 hex chars (SHA-256), got {}: {}",
        hash.len(),
        hash
    );
    assert!(
        hash.chars().all(|c| c.is_ascii_hexdigit()),
        "content_hash should be valid hex, got: {hash}"
    );
}

// === Commit: sequential checkpoints ===

#[test]
fn test_commit_sequential_checkpoints_increment() {
    let env = common::TempEnv::with_identity();
    let path = env.create_file("sequential.txt", "version 1");

    for i in 1..=4 {
        let content = format!("version {i} with enough unique content");
        fs::write(&path, &content).unwrap();
        let output = env.run(
            &[
                "commit",
                path.to_str().unwrap(),
                "-m",
                &format!("v{i}"),
                "--json",
            ],
            None,
        );
        common::assert_exit_success(&output, &format!("commit v{i}"));
        let json = common::assert_json_valid(&output, &format!("commit v{i}"));
        assert_eq!(
            json["checkpoint"].as_u64().unwrap(),
            i,
            "checkpoint number should be {i}"
        );
    }
}

// === Verify: format dispatch ===

#[test]
fn test_verify_unknown_extension_errors() {
    let env = common::TempEnv::with_identity();
    let path = env.create_file("evidence.xyz", "not valid evidence");
    let output = env.run_expect_failure(&["verify", path.to_str().unwrap()], None);
    common::assert_no_panic(&output, "verify unknown extension");
    let combined = format!("{}{}", output.stdout, output.stderr);
    assert!(
        combined.contains("Unknown file format") || combined.contains("xyz"),
        "should mention unknown format, got: {combined}"
    );
}

#[test]
fn test_verify_random_bytes_as_cpoe_errors() {
    let env = common::TempEnv::with_identity();
    let path = env.dir.path().join("fake.cpoe");
    fs::write(&path, &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF]).unwrap();
    let output = env.run_expect_failure(&["verify", path.to_str().unwrap()], None);
    common::assert_no_panic(&output, "verify random bytes as CPoE");
}

#[test]
fn test_verify_invalid_json_evidence_errors() {
    let env = common::TempEnv::with_identity();
    let path = env.create_file("bad.json", "{invalid json content}");
    let output = env.run_expect_failure(&["verify", path.to_str().unwrap()], None);
    common::assert_no_panic(&output, "verify invalid JSON");
}

#[test]
fn test_verify_valid_json_wrong_structure_errors() {
    let env = common::TempEnv::with_identity();
    let path = env.create_file("wrong.json", r#"{"name": "not evidence"}"#);
    let output = env.run_expect_failure(&["verify", path.to_str().unwrap()], None);
    common::assert_no_panic(&output, "verify wrong JSON structure");
}

// === Link: edge cases ===

#[test]
fn test_link_source_not_found_errors() {
    let env = common::TempEnv::with_identity();
    let export = env.create_file("export.pdf", "PDF content");
    let output = env.run_expect_failure(
        &[
            "link",
            "/tmp/nonexistent_source_xyz.txt",
            export.to_str().unwrap(),
        ],
        None,
    );
    common::assert_no_panic(&output, "link missing source");
    let combined = format!("{}{}", output.stdout, output.stderr);
    assert!(
        combined.contains("not found") || combined.contains("Source"),
        "should mention missing source"
    );
}

#[test]
fn test_link_export_not_found_errors() {
    let env = common::TempEnv::with_identity();
    let source = env.create_file("source.txt", "source content");
    let output = env.run_expect_failure(
        &[
            "link",
            source.to_str().unwrap(),
            "/tmp/nonexistent_export_xyz.pdf",
        ],
        None,
    );
    common::assert_no_panic(&output, "link missing export");
    let combined = format!("{}{}", output.stdout, output.stderr);
    assert!(
        combined.contains("not found") || combined.contains("Export"),
        "should mention missing export"
    );
}

#[test]
fn test_link_source_without_evidence_chain_errors() {
    let env = common::TempEnv::with_identity();
    let source = env.create_file("untracked.txt", "no evidence for this file");
    let export = env.create_file("export.pdf", "PDF content");
    let output = env.run_expect_failure(
        &[
            "link",
            source.to_str().unwrap(),
            export.to_str().unwrap(),
            "-m",
            "test link",
        ],
        None,
    );
    common::assert_no_panic(&output, "link untracked source");
    let combined = format!("{}{}", output.stdout, output.stderr);
    assert!(
        combined.contains("No evidence")
            || combined.contains("chain")
            || combined.contains("Track"),
        "should mention missing evidence chain, got: {combined}"
    );
}

// === Quiet mode ===

#[test]
fn test_commit_quiet_mode_suppresses_output() {
    let env = common::TempEnv::with_identity();
    let path = env.create_file("quiet.txt", "quiet mode test");
    let output = env.run(
        &["commit", path.to_str().unwrap(), "-m", "quiet", "-q"],
        None,
    );
    common::assert_exit_success(&output, "commit -q");
    assert!(
        output.stdout.trim().is_empty(),
        "quiet mode should produce no stdout, got: '{}'",
        output.stdout
    );
}
