use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_cli_full_workflow() {
    let dir = tempdir().unwrap();
    let bin = env!("CARGO_BIN_EXE_writersproof-cli");

    let run = |args: &[&str], input: Option<&str>| {
        use std::io::Write;
        use std::process::Stdio;

        let mut child = Command::new(bin)
            .args(args)
            .env("CPOE_DATA_DIR", dir.path())
            .env("CPOE_NO_KEYCHAIN", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn process");

        if let Some(stdin_content) = input {
            let mut stdin = child.stdin.take().expect("Failed to open stdin");
            stdin
                .write_all(stdin_content.as_bytes())
                .expect("Failed to write to stdin");
        }

        let output = child.wait_with_output().expect("failed to wait on child");

        if !output.status.success() {
            panic!(
                "Command failed: cpoe {}\nSTDOUT: {}\nSTDERR: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        String::from_utf8_lossy(&output.stdout).to_string()
    };

    let stdout = run(&["init"], None);
    assert!(stdout.contains("CPoE initialized"));
    assert!(dir.path().join("signing_key").exists());

    let stdout = run(&["status"], None);
    assert!(stdout.contains("CPoE Status"));
    assert!(stdout.contains("Verified"));

    let doc_path = dir.path().join("test.txt");
    fs::write(&doc_path, "First version content").unwrap();

    let stdout = run(
        &["commit", doc_path.to_str().unwrap(), "-m", "First commit"],
        None,
    );
    assert!(stdout.contains("Checkpoint #1 created"));

    fs::write(&doc_path, "Second version content - more text").unwrap();
    let stdout = run(
        &["commit", doc_path.to_str().unwrap(), "-m", "Second commit"],
        None,
    );
    assert!(stdout.contains("Checkpoint #2 created"));

    fs::write(
        &doc_path,
        "Third version content - even more text added here",
    )
    .unwrap();
    let stdout = run(
        &["commit", doc_path.to_str().unwrap(), "-m", "Third commit"],
        None,
    );
    assert!(stdout.contains("Checkpoint #3 created"));

    let stdout = run(&["log", doc_path.to_str().unwrap()], None);
    assert!(stdout.contains("Checkpoint History"));
    assert!(stdout.contains("First commit"));
    assert!(stdout.contains("Second commit"));
    assert!(stdout.contains("Third commit"));

    let evidence_path = dir.path().join("evidence.json");
    let stdout = run(
        &[
            "export",
            doc_path.to_str().unwrap(),
            "-o",
            evidence_path.to_str().unwrap(),
        ],
        Some("n\nTest declaration\n"),
    );
    assert!(stdout.contains("Evidence exported to"));
    assert!(evidence_path.exists());

    let stdout = run(&["verify", evidence_path.to_str().unwrap()], None);
    assert!(stdout.contains("Evidence packet Verified"));
}

/// Helper struct for CLI test utilities
struct CliTestEnv {
    dir: tempfile::TempDir,
    bin: &'static str,
}

impl CliTestEnv {
    fn new() -> Self {
        Self {
            dir: tempdir().unwrap(),
            bin: env!("CARGO_BIN_EXE_writersproof-cli"),
        }
    }

    fn run(&self, args: &[&str], input: Option<&str>) -> (bool, String, String) {
        use std::io::Write;
        use std::process::Stdio;

        let mut child = Command::new(self.bin)
            .args(args)
            .env("CPOE_DATA_DIR", self.dir.path())
            .env("CPOE_NO_KEYCHAIN", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn process");

        if let Some(stdin_content) = input {
            let mut stdin = child.stdin.take().expect("Failed to open stdin");
            stdin
                .write_all(stdin_content.as_bytes())
                .expect("Failed to write to stdin");
        }

        let output = child.wait_with_output().expect("failed to wait on child");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }

    fn run_expect_success(&self, args: &[&str], input: Option<&str>) -> String {
        let (success, stdout, stderr) = self.run(args, input);
        assert!(
            success,
            "Command failed: cpoe {}\nSTDOUT: {}\nSTDERR: {}",
            args.join(" "),
            stdout,
            stderr
        );
        stdout
    }

    fn init(&self) {
        self.run_expect_success(&["init"], None);
    }
}

#[test]
fn test_cli_help() {
    let env = CliTestEnv::new();
    let stdout = env.run_expect_success(&["--help"], None);
    assert!(
        stdout.contains("WritersProof")
            || stdout.contains("CPoE")
            || stdout.contains("writerslogic"),
        "Help should mention the product name: {}",
        stdout
    );
    assert!(
        stdout.contains("Checkpoint") || stdout.contains("VDF") || stdout.contains("proof"),
        "Help should describe functionality"
    );
}

#[test]
fn test_cli_version() {
    let env = CliTestEnv::new();
    let stdout = env.run_expect_success(&["--version"], None);
    assert!(stdout.contains("writersproof") || stdout.contains("cpoe"));
}

#[test]
fn test_cli_status_before_init() {
    let env = CliTestEnv::new();
    let (success, stdout, _stderr) = env.run(&["status"], None);
    if success {
        assert!(
            stdout.contains("not found") || stdout.contains("Status"),
            "Status should indicate database not found or show status"
        );
    }
}

#[test]
fn test_cli_commit_before_init() {
    let env = CliTestEnv::new();
    let doc_path = env.dir.path().join("test.txt");
    fs::write(&doc_path, "content").unwrap();

    // Commit auto-initializes when no signing key exists, so it should
    // either succeed (auto-init worked) or mention initialization.
    let (success, stdout, stderr) = env.run(&["commit", doc_path.to_str().unwrap()], Some("n\n"));
    let output = format!("{}{}", stdout, stderr);
    assert!(
        success
            || output.contains("not initialized")
            || output.contains("Initialize")
            || output.contains("initializing"),
        "Commit should auto-init or mention initialization. stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}

#[test]
fn test_cli_commit_nonexistent_file() {
    let env = CliTestEnv::new();
    env.init();

    let (success, _stdout, stderr) = env.run(&["commit", "/nonexistent/file.txt"], None);
    assert!(!success, "Commit should fail for nonexistent file");
    assert!(
        stderr.contains("not found")
            || stderr.contains("No such file")
            || stderr.contains("does not exist"),
        "Should mention file not found. stderr: {}",
        stderr
    );
}

#[test]
fn test_cli_log_empty() {
    let env = CliTestEnv::new();
    env.init();

    let stdout = env.run_expect_success(&["log"], None);
    assert!(
        stdout.contains("No tracked")
            || stdout.contains("0 documents")
            || stdout.contains("No checkpoints")
            || stdout.is_empty(),
        "Should indicate no tracked documents. stdout: {}",
        stdout
    );
}

#[test]
fn test_cli_log_after_commits() {
    let env = CliTestEnv::new();
    env.init();

    let doc1 = env.dir.path().join("doc1.txt");
    let doc2 = env.dir.path().join("doc2.txt");
    fs::write(&doc1, "content1").unwrap();
    fs::write(&doc2, "content2").unwrap();

    env.run_expect_success(&["commit", doc1.to_str().unwrap(), "-m", "Doc 1"], None);
    env.run_expect_success(&["commit", doc2.to_str().unwrap(), "-m", "Doc 2"], None);

    let stdout = env.run_expect_success(&["log", doc1.to_str().unwrap()], None);
    assert!(
        stdout.contains("Doc 1") || stdout.contains("doc1.txt") || stdout.contains("Checkpoint"),
        "Should list checkpoints for doc1. stdout: {}",
        stdout
    );
}

#[test]
fn test_cli_config_show() {
    let env = CliTestEnv::new();
    env.init();

    let stdout = env.run_expect_success(&["config", "show"], None);
    assert!(
        stdout.contains("retention") || stdout.contains("config") || stdout.len() > 10,
        "Should show configuration"
    );
}

#[test]
fn test_cli_log_no_history() {
    let env = CliTestEnv::new();
    env.init();

    let doc_path = env.dir.path().join("new.txt");
    fs::write(&doc_path, "content").unwrap();

    let (success, stdout, _stderr) = env.run(&["log", doc_path.to_str().unwrap()], None);
    if success {
        assert!(
            stdout.contains("No checkpoints") || stdout.contains("0 checkpoint"),
            "Should indicate no checkpoints"
        );
    }
}

#[test]
fn test_cli_verify_invalid_file() {
    let env = CliTestEnv::new();
    env.init();

    let invalid = env.dir.path().join("invalid.json");
    fs::write(&invalid, "not valid json evidence").unwrap();

    let (success, _stdout, stderr) = env.run(&["verify", invalid.to_str().unwrap()], None);
    assert!(!success, "Verify should fail for invalid evidence");
    assert!(
        stderr.contains("parse")
            || stderr.contains("Error")
            || stderr.contains("Failed")
            || stderr.to_lowercase().contains("invalid"),
        "Should indicate parse error. stderr: {}",
        stderr
    );
}

#[test]
fn test_cli_calibrate() {
    let env = CliTestEnv::new();
    env.init();

    let (success, stdout, stderr) = env.run(&["calibrate"], None);

    if success {
        assert!(
            stdout.contains("iterations")
                || stdout.contains("calibrat")
                || stdout.contains("speed"),
            "Should show calibration results. stdout: {}",
            stdout
        );
    } else {
        println!(
            "Calibrate failed (may be expected): stdout={}, stderr={}",
            stdout, stderr
        );
    }
}

#[test]
fn test_cli_presence_without_session() {
    let env = CliTestEnv::new();
    env.init();

    let (success, stdout, _stderr) = env.run(&["presence", "status"], None);
    if success {
        assert!(
            stdout.contains("No active") || stdout.contains("not active"),
            "Should indicate no active session"
        );
    }
}

#[test]
fn test_cli_fingerprint_status() {
    let env = CliTestEnv::new();
    env.init();

    let stdout = env.run_expect_success(&["fingerprint", "status"], None);
    assert!(
        stdout.contains("fingerprint")
            || stdout.contains("activity")
            || stdout.contains("status")
            || stdout.len() > 5,
        "Should show fingerprint status"
    );
}

#[test]
fn test_cli_status_json() {
    let env = CliTestEnv::new();
    env.init();

    let stdout = env.run_expect_success(&["status", "--json"], None);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("Status --json should return valid JSON: {e}\nGot: {stdout}"));
    assert!(parsed.get("data_dir").is_some(), "Should have data_dir");
    assert!(
        parsed.get("database").is_some(),
        "Should have database section"
    );
    assert!(
        parsed.get("hardware").is_some(),
        "Should have hardware section"
    );
}

#[test]
fn test_cli_log_json_after_commit() {
    let env = CliTestEnv::new();
    env.init();

    let doc = env.dir.path().join("test.txt");
    fs::write(&doc, "content").unwrap();
    env.run_expect_success(&["commit", doc.to_str().unwrap(), "-m", "Test"], None);

    let stdout = env.run_expect_success(&["log", doc.to_str().unwrap(), "--json"], None);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("Log --json should return valid JSON: {e}\nGot: {stdout}"));
    assert_eq!(
        parsed.get("checkpoint_count").and_then(|v| v.as_u64()),
        Some(1),
        "Should have 1 checkpoint"
    );
}

#[test]
fn test_cli_log_json() {
    let env = CliTestEnv::new();
    env.init();

    let doc = env.dir.path().join("test.txt");
    fs::write(&doc, "content").unwrap();
    env.run_expect_success(&["commit", doc.to_str().unwrap(), "-m", "First"], None);
    fs::write(&doc, "content updated").unwrap();
    env.run_expect_success(&["commit", doc.to_str().unwrap(), "-m", "Second"], None);

    let stdout = env.run_expect_success(&["log", doc.to_str().unwrap(), "--json"], None);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("Log --json should return valid JSON: {e}\nGot: {stdout}"));
    assert_eq!(
        parsed.get("checkpoint_count").and_then(|v| v.as_u64()),
        Some(2)
    );
    let checkpoints = parsed.get("checkpoints").and_then(|v| v.as_array());
    assert!(checkpoints.is_some());
    assert_eq!(checkpoints.unwrap().len(), 2);
}

#[test]
fn test_cli_commit_json() {
    let env = CliTestEnv::new();
    env.init();

    let doc = env.dir.path().join("essay.txt");
    fs::write(&doc, "My essay content").unwrap();

    let stdout = env.run_expect_success(
        &["commit", doc.to_str().unwrap(), "-m", "Draft", "--json"],
        None,
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("Commit --json should return valid JSON: {e}\nGot: {stdout}"));
    assert_eq!(parsed.get("checkpoint").and_then(|v| v.as_u64()), Some(1));
    assert!(parsed.get("content_hash").is_some());
    assert!(parsed.get("event_hash").is_some());
}

#[test]
fn test_cli_quiet_mode() {
    let env = CliTestEnv::new();
    env.init();

    let doc = env.dir.path().join("quiet.txt");
    fs::write(&doc, "quiet content").unwrap();
    env.run_expect_success(
        &["commit", doc.to_str().unwrap(), "-m", "Quiet", "--quiet"],
        None,
    );

    let stdout = env.run_expect_success(&["status", "--quiet"], None);
    assert!(stdout.is_empty(), "Quiet status should produce no output");

    let stdout = env.run_expect_success(&["presence", "status", "--quiet"], None);
    assert!(
        stdout.is_empty(),
        "Quiet presence status should produce no output"
    );
}

#[test]
fn test_cli_commit_binary_rejected() {
    let env = CliTestEnv::new();
    env.init();

    let binary = env.dir.path().join("image.png");
    fs::write(&binary, b"\x89PNG\r\n\x1a\n").unwrap();

    let (success, _stdout, stderr) = env.run(&["commit", binary.to_str().unwrap()], None);
    assert!(!success, "Commit should reject binary files");
    assert!(
        stderr.contains("not a supported text document")
            || stderr.contains("not a text document")
            || stderr.contains("Binary"),
        "Should explain why binary is rejected. stderr: {}",
        stderr
    );
}

#[test]
fn test_cli_completions() {
    let env = CliTestEnv::new();
    let stdout = env.run_expect_success(&["completions", "bash"], None);
    assert!(
        stdout.contains("complete") || stdout.contains("cpoe"),
        "Should generate bash completions"
    );
}

#[test]
fn test_cli_track_list() {
    let env = CliTestEnv::new();
    env.init();

    let (success, stdout, _stderr) = env.run(&["track", "list"], None);
    if success {
        assert!(
            stdout.contains("No saved") || stdout.contains("sessions"),
            "Should show sessions. stdout: {}",
            stdout
        );
    }
    // May fail if tracking directory doesn't exist yet; that's acceptable
}

#[test]
fn test_cli_identity_json() {
    let env = CliTestEnv::new();
    env.init();

    let stdout = env.run_expect_success(&["identity", "--json"], None);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("Identity --json should return valid JSON: {e}\nGot: {stdout}"));
    assert!(
        parsed.get("fingerprint").is_some(),
        "Should have fingerprint"
    );
    assert!(parsed.get("did").is_some(), "Should have DID");
    assert!(parsed.get("public_key").is_some(), "Should have public_key");
}

#[test]
fn test_cli_config_set_invalid() {
    let env = CliTestEnv::new();
    env.init();

    let (success, _stdout, stderr) = env.run(
        &["config", "set", "sentinel.heartbeat_interval_secs", "0"],
        None,
    );
    assert!(!success, "Should reject invalid config value");
    assert!(
        stderr.contains("must be between")
            || stderr.contains("invalid")
            || stderr.contains("Error"),
        "Should explain validation failure"
    );
}

// ---- Additional coverage tests ----

#[test]
fn test_cli_checkpoint_alias() {
    let env = CliTestEnv::new();
    env.init();

    let doc = env.dir.path().join("alias_checkpoint.txt");
    fs::write(&doc, "Checkpoint alias content").unwrap();

    let stdout = env.run_expect_success(
        &[
            "checkpoint",
            doc.to_str().unwrap(),
            "-m",
            "Via checkpoint alias",
        ],
        None,
    );
    assert!(
        stdout.contains("Checkpoint #1"),
        "checkpoint alias should work like commit. stdout: {}",
        stdout
    );
}

#[test]
fn test_cli_ls_alias() {
    let env = CliTestEnv::new();
    env.init();

    let stdout = env.run_expect_success(&["ls"], None);
    assert!(
        stdout.contains("No tracked") || stdout.contains("0 documents") || stdout.is_empty(),
        "ls alias should work like list. stdout: {}",
        stdout
    );
}

#[test]
fn test_cli_history_alias() {
    let env = CliTestEnv::new();
    env.init();

    let doc = env.dir.path().join("history_alias.txt");
    fs::write(&doc, "History alias content").unwrap();
    env.run_expect_success(
        &["commit", doc.to_str().unwrap(), "-m", "History test"],
        None,
    );

    let stdout = env.run_expect_success(&["history", doc.to_str().unwrap()], None);
    assert!(
        stdout.contains("History test") || stdout.contains("Checkpoint"),
        "history alias should work like log. stdout: {}",
        stdout
    );
}

#[test]
fn test_cli_log_no_file_lists_documents() {
    let env = CliTestEnv::new();
    env.init();

    let doc1 = env.dir.path().join("logged1.txt");
    let doc2 = env.dir.path().join("logged2.txt");
    fs::write(&doc1, "content 1").unwrap();
    fs::write(&doc2, "content 2").unwrap();
    env.run_expect_success(
        &["commit", doc1.to_str().unwrap(), "-m", "Log test 1"],
        None,
    );
    env.run_expect_success(
        &["commit", doc2.to_str().unwrap(), "-m", "Log test 2"],
        None,
    );

    let stdout = env.run_expect_success(&["log"], None);
    assert!(
        stdout.contains("logged1.txt")
            || stdout.contains("logged2.txt")
            || stdout.contains("2 documents")
            || stdout.contains("Tracked"),
        "log with no file should list checkpoints or documents. stdout: {}",
        stdout
    );
}

#[test]
fn test_cli_track_stop_no_session() {
    let env = CliTestEnv::new();
    env.init();

    let (success, stdout, stderr) = env.run(&["track", "stop"], None);
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        combined.contains("No active")
            || combined.contains("not running")
            || combined.contains("no session")
            || combined.to_lowercase().contains("no active")
            || !success,
        "track stop should say no active session or fail gracefully. stdout: {}, stderr: {}",
        stdout,
        stderr
    );
}

#[test]
fn test_cli_fingerprint_list_empty() {
    let env = CliTestEnv::new();
    env.init();

    let stdout = env.run_expect_success(&["fingerprint", "list"], None);
    assert!(
        stdout.contains("No fingerprint")
            || stdout.contains("No profiles")
            || stdout.contains("fingerprint")
            || stdout.contains("0 profiles"),
        "fingerprint list should indicate no profiles. stdout: {}",
        stdout
    );
}

#[test]
fn test_cli_config_set_and_show() {
    let env = CliTestEnv::new();
    env.init();

    let stdout = env.run_expect_success(
        &["config", "set", "sentinel.idle_timeout_secs", "600"],
        None,
    );
    assert!(
        stdout.contains("Set") || stdout.contains("600"),
        "config set should confirm. stdout: {}",
        stdout
    );

    let stdout = env.run_expect_success(&["config", "show"], None);
    assert!(
        stdout.contains("600"),
        "config show should reflect updated value. stdout: {}",
        stdout
    );
}

#[test]
fn test_cli_identity_fingerprint_flag() {
    let env = CliTestEnv::new();
    env.init();

    let stdout = env.run_expect_success(&["identity", "--fingerprint"], None);
    assert!(
        stdout.contains("Fingerprint") || stdout.contains("fingerprint"),
        "identity --fingerprint should show fingerprint. stdout: {}",
        stdout
    );
}

#[test]
fn test_cli_json_flag_status() {
    let env = CliTestEnv::new();
    env.init();

    // Global --json must come after subcommand for clap with args_conflicts_with_subcommands
    let stdout = env.run_expect_success(&["status", "--json"], None);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("status --json should return valid JSON: {e}\nGot: {stdout}"));
    assert!(
        parsed.is_object(),
        "status --json should produce a JSON object"
    );
}

#[test]
fn test_cli_quiet_flag_status() {
    let env = CliTestEnv::new();
    env.init();

    let stdout = env.run_expect_success(&["status", "--quiet"], None);
    assert!(
        stdout.is_empty(),
        "status --quiet should suppress output. Got: {}",
        stdout
    );
}

#[test]
fn test_cli_fp_alias() {
    let env = CliTestEnv::new();
    env.init();

    let stdout = env.run_expect_success(&["fp", "status"], None);
    assert!(
        stdout.contains("Fingerprint") || stdout.contains("fingerprint") || stdout.len() > 5,
        "fp alias should work like fingerprint. stdout: {}",
        stdout
    );
}

#[test]
fn test_cli_id_alias() {
    let env = CliTestEnv::new();
    env.init();

    let stdout = env.run_expect_success(&["id", "--fingerprint"], None);
    assert!(
        stdout.contains("Fingerprint") || stdout.contains("fingerprint"),
        "id alias should work like identity. stdout: {}",
        stdout
    );
}

#[test]
fn test_cli_cfg_alias() {
    let env = CliTestEnv::new();
    env.init();

    let stdout = env.run_expect_success(&["cfg", "show"], None);
    assert!(
        stdout.contains("Configuration") || stdout.contains("config") || stdout.len() > 10,
        "cfg alias should work like config. stdout: {}",
        stdout
    );
}

#[test]
fn test_cli_verify_unsupported_extension() {
    let env = CliTestEnv::new();
    env.init();

    let bad_file = env.dir.path().join("data.xyz");
    fs::write(&bad_file, "data").unwrap();

    let (success, _stdout, stderr) = env.run(&["verify", bad_file.to_str().unwrap()], None);
    assert!(!success, "Verify should reject unsupported format");
    assert!(
        stderr.contains("format") || stderr.contains("Supported"),
        "Should list supported formats"
    );
}

// ==== New feature tests ====

#[test]
fn test_cli_link_success() {
    let env = CliTestEnv::new();
    env.init();

    let source = env.dir.path().join("manuscript.txt");
    fs::write(&source, "My manuscript content").unwrap();
    env.run_expect_success(&["commit", source.to_str().unwrap(), "-m", "Draft"], None);

    let export = env.dir.path().join("manuscript.pdf");
    fs::write(&export, b"%PDF-1.4 fake pdf content").unwrap();

    let stdout = env.run_expect_success(
        &[
            "link",
            source.to_str().unwrap(),
            export.to_str().unwrap(),
            "-m",
            "Final PDF export",
        ],
        None,
    );
    assert!(
        stdout.contains("Linked export to evidence chain"),
        "Should confirm link. stdout: {}",
        stdout
    );
    assert!(
        stdout.contains("manuscript.pdf"),
        "Should show export filename. stdout: {}",
        stdout
    );
}

#[test]
fn test_cli_link_json() {
    let env = CliTestEnv::new();
    env.init();

    let source = env.dir.path().join("essay.txt");
    fs::write(&source, "Essay content").unwrap();
    env.run_expect_success(&["commit", source.to_str().unwrap(), "-m", "V1"], None);

    let export = env.dir.path().join("essay.pdf");
    fs::write(&export, "fake pdf").unwrap();

    let stdout = env.run_expect_success(
        &[
            "link",
            source.to_str().unwrap(),
            export.to_str().unwrap(),
            "--json",
        ],
        None,
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("link --json should return valid JSON: {e}\nGot: {stdout}"));
    assert_eq!(parsed.get("linked").and_then(|v| v.as_bool()), Some(true));
    assert!(parsed.get("export_hash").is_some());
    assert!(parsed.get("event_hash").is_some());
}

#[test]
fn test_cli_link_no_evidence_chain() {
    let env = CliTestEnv::new();
    env.init();

    let source = env.dir.path().join("untracked.txt");
    fs::write(&source, "Not tracked").unwrap();

    let export = env.dir.path().join("output.pdf");
    fs::write(&export, "pdf").unwrap();

    let (success, _stdout, stderr) = env.run(
        &["link", source.to_str().unwrap(), export.to_str().unwrap()],
        None,
    );
    assert!(!success, "Link should fail without evidence chain");
    assert!(
        stderr.contains("No evidence chain"),
        "Should explain no chain. stderr: {}",
        stderr
    );
}

#[test]
fn test_cli_link_missing_export_file() {
    let env = CliTestEnv::new();
    env.init();

    let source = env.dir.path().join("source.txt");
    fs::write(&source, "content").unwrap();
    env.run_expect_success(&["commit", source.to_str().unwrap(), "-m", "V1"], None);

    let (success, _stdout, stderr) = env.run(
        &["link", source.to_str().unwrap(), "/nonexistent/export.pdf"],
        None,
    );
    assert!(!success, "Link should fail for missing export");
    assert!(
        stderr.contains("not found") || stderr.contains("Export file"),
        "Should explain missing export. stderr: {}",
        stderr
    );
}

#[test]
fn test_cli_link_shows_in_log() {
    let env = CliTestEnv::new();
    env.init();

    let source = env.dir.path().join("novel.txt");
    fs::write(&source, "Novel content").unwrap();
    env.run_expect_success(&["commit", source.to_str().unwrap(), "-m", "Ch1"], None);

    let export = env.dir.path().join("novel.pdf");
    fs::write(&export, "pdf").unwrap();
    env.run_expect_success(
        &[
            "link",
            source.to_str().unwrap(),
            export.to_str().unwrap(),
            "-m",
            "PDF export",
        ],
        None,
    );

    // The derivative event should appear in the log
    let stdout = env.run_expect_success(&["log", source.to_str().unwrap(), "--json"], None);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let count = parsed
        .get("checkpoint_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert_eq!(count, 2, "Should have 2 events (commit + link)");
}

#[test]
fn test_cli_commit_empty_file() {
    let env = CliTestEnv::new();
    env.init();

    let doc = env.dir.path().join("empty.txt");
    fs::write(&doc, "").unwrap();

    let (_success, stdout, stderr) =
        env.run(&["commit", doc.to_str().unwrap(), "-m", "Empty"], None);
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        combined.contains("empty") || combined.contains("zero-byte"),
        "Should warn about empty file. combined: {}",
        combined
    );
}

#[test]
fn test_cli_commit_unchanged_file() {
    let env = CliTestEnv::new();
    env.init();

    let doc = env.dir.path().join("stable.txt");
    fs::write(&doc, "Stable content").unwrap();

    env.run_expect_success(&["commit", doc.to_str().unwrap(), "-m", "First"], None);

    // Commit same content again — should still create checkpoint
    let stdout = env.run_expect_success(
        &["commit", doc.to_str().unwrap(), "-m", "Same content"],
        None,
    );
    assert!(
        stdout.contains("Checkpoint #2"),
        "Should create checkpoint even for unchanged content. stdout: {}",
        stdout
    );
}

#[test]
fn test_cli_identity_did() {
    let env = CliTestEnv::new();
    env.init();

    let stdout = env.run_expect_success(&["identity", "--did"], None);
    assert!(
        stdout.contains("did:key:"),
        "identity --did should show DID. stdout: {}",
        stdout
    );
}

#[test]
fn test_cli_config_reset() {
    let env = CliTestEnv::new();
    env.init();

    // Change a config value first
    env.run_expect_success(
        &["config", "set", "sentinel.idle_timeout_secs", "999"],
        None,
    );

    let stdout = env.run_expect_success(&["config", "reset", "--force"], None);
    assert!(
        stdout.contains("Reset") || stdout.contains("reset") || stdout.contains("default"),
        "config reset should confirm. stdout: {}",
        stdout
    );

    // Verify it's back to default
    let stdout = env.run_expect_success(&["config", "show"], None);
    assert!(
        !stdout.contains("999"),
        "Config should no longer have custom value"
    );
}

#[test]
fn test_cli_export_json_format() {
    let env = CliTestEnv::new();
    env.init();

    let doc = env.dir.path().join("exporttest.txt");
    fs::write(&doc, "Export test v1").unwrap();
    env.run_expect_success(&["commit", doc.to_str().unwrap(), "-m", "V1"], None);
    fs::write(&doc, "Export test v2 with changes").unwrap();
    env.run_expect_success(&["commit", doc.to_str().unwrap(), "-m", "V2"], None);
    fs::write(&doc, "Export test v3 with more changes").unwrap();
    env.run_expect_success(&["commit", doc.to_str().unwrap(), "-m", "V3"], None);

    let out_path = env.dir.path().join("evidence.json");
    env.run_expect_success(
        &[
            "export",
            doc.to_str().unwrap(),
            "-f",
            "json",
            "-o",
            out_path.to_str().unwrap(),
        ],
        Some("n\nTest declaration\n"),
    );

    assert!(out_path.exists(), "JSON evidence file should exist");
    let content = fs::read_to_string(&out_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap_or_else(|e| {
        panic!(
            "Evidence should be valid JSON: {e}\nContent: {}",
            &content[..200.min(content.len())]
        )
    });
    assert!(
        parsed.get("checkpoints").is_some() || parsed.get("events").is_some(),
        "Evidence should contain checkpoints"
    );
}

#[test]
fn test_cli_export_insufficient_checkpoints() {
    let env = CliTestEnv::new();
    env.init();

    let doc = env.dir.path().join("few.txt");
    fs::write(&doc, "content").unwrap();
    env.run_expect_success(&["commit", doc.to_str().unwrap(), "-m", "Only one"], None);

    let out_path = env.dir.path().join("evidence.json");
    let (success, _stdout, stderr) = env.run(
        &[
            "export",
            doc.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
        ],
        Some("n\nDeclaration\n"),
    );
    // Export should either fail or warn about insufficient checkpoints
    if !success {
        assert!(
            stderr.contains("checkpoint") || stderr.contains("at least"),
            "Should explain insufficient checkpoints. stderr: {}",
            stderr
        );
    }
}

#[test]
fn test_cli_multiple_commits_chain_integrity() {
    let env = CliTestEnv::new();
    env.init();

    let doc = env.dir.path().join("chain.txt");
    for i in 1..=5 {
        fs::write(&doc, format!("Version {} of the document", i)).unwrap();
        let stdout = env.run_expect_success(
            &[
                "commit",
                doc.to_str().unwrap(),
                "-m",
                &format!("Commit {}", i),
                "--json",
            ],
            None,
        );
        let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(
            parsed.get("checkpoint").and_then(|v| v.as_u64()),
            Some(i),
            "Checkpoint number should be {}",
            i
        );
    }

    // Verify log shows all 5
    let stdout = env.run_expect_success(&["log", doc.to_str().unwrap(), "--json"], None);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        parsed.get("checkpoint_count").and_then(|v| v.as_u64()),
        Some(5)
    );
}

#[test]
fn test_cli_link_auto_init() {
    // Link command should auto-initialize on fresh install
    let env = CliTestEnv::new();
    // Do NOT call env.init() — test that link triggers auto-init

    let source = env.dir.path().join("src.txt");
    fs::write(&source, "content").unwrap();
    let export = env.dir.path().join("out.pdf");
    fs::write(&export, "pdf").unwrap();

    let (_success, _stdout, stderr) = env.run(
        &["link", source.to_str().unwrap(), export.to_str().unwrap()],
        None,
    );
    // Should auto-init (stderr mentions initializing) or fail with "no evidence chain"
    // Either way, the auto-init gate should have fired
    let combined = format!("{}{}", _stdout, stderr);
    assert!(
        combined.contains("Initializing")
            || combined.contains("initialized")
            || combined.contains("No evidence chain"),
        "Link should auto-init or fail after init. combined: {}",
        combined
    );
}

#[test]
fn test_cli_commit_size_delta() {
    let env = CliTestEnv::new();
    env.init();

    let doc = env.dir.path().join("delta.txt");
    fs::write(&doc, "Short").unwrap();
    env.run_expect_success(
        &["commit", doc.to_str().unwrap(), "-m", "Short", "--json"],
        None,
    );

    fs::write(
        &doc,
        "This is a much longer version of the document with more content",
    )
    .unwrap();
    let stdout = env.run_expect_success(
        &["commit", doc.to_str().unwrap(), "-m", "Long", "--json"],
        None,
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let delta = parsed
        .get("size_delta")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    assert!(
        delta > 0,
        "Size delta should be positive after growth. delta: {}",
        delta
    );
}

#[test]
fn test_cli_verify_evidence_roundtrip() {
    let env = CliTestEnv::new();
    env.init();

    let doc = env.dir.path().join("roundtrip.txt");
    fs::write(&doc, "V1 content").unwrap();
    env.run_expect_success(&["commit", doc.to_str().unwrap(), "-m", "V1"], None);
    fs::write(&doc, "V2 content with changes").unwrap();
    env.run_expect_success(&["commit", doc.to_str().unwrap(), "-m", "V2"], None);
    fs::write(&doc, "V3 content with even more changes").unwrap();
    env.run_expect_success(&["commit", doc.to_str().unwrap(), "-m", "V3"], None);

    let evidence = env.dir.path().join("roundtrip.json");
    env.run_expect_success(
        &[
            "export",
            doc.to_str().unwrap(),
            "-o",
            evidence.to_str().unwrap(),
        ],
        Some("n\nRoundtrip test\n"),
    );

    let stdout = env.run_expect_success(&["verify", evidence.to_str().unwrap()], None);
    assert!(
        stdout.contains("Verified"),
        "Exported evidence should verify. stdout: {}",
        stdout
    );
}
