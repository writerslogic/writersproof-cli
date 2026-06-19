// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! CPoE CLI — cryptographic authorship witnessing.

use std::io::IsTerminal;

use anyhow::Result;
use clap::{CommandFactory, Parser};

mod cli;
mod cmd_attest;
mod cmd_beacon;
mod cmd_commit;
mod cmd_config;
mod cmd_credential;
mod cmd_daemon;
mod cmd_export;
mod cmd_fingerprint;
mod cmd_forensics;
mod cmd_identity;
mod cmd_init;
mod cmd_link;
mod cmd_log;
mod cmd_presence;
mod cmd_report;
mod cmd_snapshot;
mod cmd_status;
mod cmd_track;
mod cmd_verify;
mod output;
mod smart_defaults;
mod spec;
mod util;

use cli::{Cli, Commands};
use output::OutputMode;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {:#}", e);
        eprintln!();
        eprintln!("For more information, try 'cpoe --help'");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let out = OutputMode::new(cli.json, cli.quiet);

    maybe_auto_start(&cli, &out).await?;
    maybe_auto_init(&cli, &out)?;

    match cli.command {
        Some(Commands::Init {}) => cmd_init::cmd_init()?,
        Some(Commands::Identity {
            fingerprint,
            did,
            mnemonic,
            recover,
        }) => cmd_identity::cmd_identity(fingerprint, did, mnemonic, recover, out.json)?,
        Some(Commands::Commit {
            file,
            message,
            anchor,
        }) => cmd_commit::cmd_commit_smart(file, message, anchor, &out).await?,
        Some(Commands::Log { file }) => cmd_log::cmd_log_smart(file, &out)?,
        Some(Commands::Export {
            file,
            tier,
            output,
            format,
            no_beacons,
            beacon_timeout,
            notarize,
        }) => {
            cmd_export::cmd_export(
                &file,
                &tier,
                output,
                &format,
                no_beacons,
                beacon_timeout,
                notarize,
                &out,
            )
            .await?
        }
        Some(Commands::Verify {
            file,
            key,
            output_war,
        }) => cmd_verify::cmd_verify(&file, key, output_war, &out)?,
        Some(Commands::Presence { action }) => cmd_presence::cmd_presence(action, &out)?,
        Some(Commands::Link {
            source,
            export,
            message,
        }) => cmd_link::cmd_link(&source, &export, message, &out)?,
        Some(Commands::Track { action, file }) => {
            cmd_track::cmd_track_smart(action, file, &out).await?
        }
        Some(Commands::Calibrate) => cmd_status::cmd_calibrate()?,
        Some(Commands::Status) => cmd_status::cmd_status(&out)?,
        Some(Commands::Start { foreground }) => cmd_daemon::cmd_start(foreground).await?,
        Some(Commands::Stop) => cmd_daemon::cmd_stop()?,
        Some(Commands::Fingerprint { action }) => cmd_fingerprint::cmd_fingerprint(action, &out)?,
        Some(Commands::Attest {
            format,
            input,
            output,
            non_interactive,
        }) => cmd_attest::cmd_attest(&format, input, output, non_interactive, &out)?,
        Some(Commands::Config { action }) => cmd_config::cmd_config(action)?,
        Some(Commands::Forensics { action }) => cmd_forensics::cmd_forensics(action, &out)?,
        Some(Commands::Beacon { action }) => cmd_beacon::cmd_beacon(action, &out)?,
        Some(Commands::Report { file, format }) => cmd_report::cmd_report(&file, &format, &out)?,
        Some(Commands::Snapshot { action }) => cmd_snapshot::cmd_snapshot(action, &out)?,
        Some(Commands::Credential { action }) => cmd_credential::cmd_credential(action, &out)?,
        Some(Commands::Completions { shell }) => {
            clap_complete::generate(shell, &mut Cli::command(), "cpoe", &mut std::io::stdout());
        }
        Some(Commands::Man) => print_manual(),
        None => {
            if let Some(path) = cli.path {
                let resolved = util::normalize_path(&path)?;
                cmd_track::cmd_track_smart(None, Some(resolved), &out).await?;
            } else {
                cmd_status::show_quick_status(&out)?;
                if out.verbose() && std::io::stdout().is_terminal() {
                    interactive_menu(&out).await?;
                }
            }
        }
    }

    Ok(())
}

async fn maybe_auto_start(cli: &Cli, out: &OutputMode) -> Result<()> {
    let should_start = cli.path.is_some()
        || cli
            .command
            .as_ref()
            .is_some_and(|cmd| cmd.needs_auto_start());

    if !should_start {
        return Ok(());
    }

    if let Ok(dir) = util::writersproof_dir() {
        if let Ok(config) = cpoe::config::CpopConfig::load_or_default(&dir) {
            if config.sentinel.auto_start {
                let daemon_manager = cpoe::DaemonManager::new(&config.data_dir);
                if !daemon_manager.is_running() {
                    if !out.quiet {
                        eprintln!("Starting CPoE daemon...");
                    }
                    if let Err(e) = cmd_daemon::cmd_start(false).await {
                        eprintln!("Warning: daemon auto-start failed: {e}");
                    }
                }
            }
        }
    }
    Ok(())
}

fn maybe_auto_init(cli: &Cli, out: &OutputMode) -> Result<()> {
    let needs_init = matches!(
        &cli.command,
        Some(Commands::Commit { .. })
            | Some(Commands::Log { .. })
            | Some(Commands::Export { .. })
            | Some(Commands::Verify { .. })
            | Some(Commands::Track { .. })
            | Some(Commands::Link { .. })
            | Some(Commands::Calibrate)
            | Some(Commands::Fingerprint { .. })
            | Some(Commands::Attest { .. })
            | Some(Commands::Presence { .. })
            | Some(Commands::Forensics { .. })
            | Some(Commands::Beacon { .. })
            | Some(Commands::Report { .. })
            | Some(Commands::Snapshot { .. })
            | Some(Commands::Credential { .. })
    ) || cli.path.is_some();

    if needs_init {
        if let Ok(dir) = util::writersproof_dir() {
            if !dir.join("signing_key").exists() {
                if !out.quiet {
                    eprintln!("Initializing CPoE for first use...");
                }
                cmd_init::cmd_init()?;
            }
        }
    }
    Ok(())
}

fn print_manual() {
    let _ = Cli::command().print_long_help();
}

async fn interactive_menu(out: &OutputMode) -> Result<()> {
    use dialoguer::{Input, Select};
    use std::path::PathBuf;

    let items = &[
        "Track a file or folder",
        "Create checkpoint",
        "View history",
        "Export evidence",
        "Verify evidence",
        "Show identity",
        "Behavioral fingerprint",
        "Presence verification",
        "Configuration",
        "Quit",
    ];

    eprintln!();
    let selection = Select::new()
        .with_prompt("What would you like to do?")
        .items(items)
        .default(0)
        .interact_opt()?;

    match selection {
        Some(0) => {
            let path: String = Input::new()
                .with_prompt("Path to file or folder")
                .interact_text()?;
            let input_path = PathBuf::from(path);
            if std::fs::symlink_metadata(&input_path)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
            {
                anyhow::bail!(
                    "path '{}' is a symlink; track the real path directly",
                    input_path.display()
                );
            }
            let resolved = util::normalize_path(&input_path)?;
            // Reject paths outside cwd and home directory (potential traversal).
            if let (Ok(cwd), Some(home)) = (std::env::current_dir(), dirs::home_dir()) {
                if !resolved.starts_with(&cwd) && !resolved.starts_with(&home) {
                    anyhow::bail!(
                        "path '{}' is outside both the current directory and home directory; \
                         use an absolute path within your home directory instead",
                        resolved.display()
                    );
                }
            }
            cmd_track::cmd_track_smart(None, Some(resolved), out).await?;
        }
        Some(1) => {
            cmd_commit::cmd_commit_smart(None, None, false, out).await?;
        }
        Some(2) => {
            cmd_log::cmd_log_smart(None, out)?;
        }
        Some(3) => {
            let path: String = Input::new().with_prompt("Path to file").interact_text()?;
            cmd_export::cmd_export(
                &PathBuf::from(path),
                "standard",
                None,
                "json",
                false,
                5,
                false,
                out,
            )
            .await?;
        }
        Some(4) => {
            let path: String = Input::new()
                .with_prompt("Path to evidence file")
                .interact_text()?;
            cmd_verify::cmd_verify(&PathBuf::from(path), None, None, out)?;
        }
        Some(5) => {
            cmd_identity::cmd_identity(false, false, false, false, out.json)?;
        }
        Some(6) => {
            let fp_items = &["View status", "List profiles", "Back"];
            let fp_sel = Select::new()
                .with_prompt("Fingerprint")
                .items(fp_items)
                .default(0)
                .interact_opt()?;
            match fp_sel {
                Some(0) => {
                    cmd_fingerprint::cmd_fingerprint(cli::FingerprintAction::Status, out)?;
                }
                Some(1) => {
                    cmd_fingerprint::cmd_fingerprint(cli::FingerprintAction::List, out)?;
                }
                _ => {}
            }
        }
        Some(7) => {
            let pr_items = &["Check status", "Start session", "Stop session", "Back"];
            let pr_sel = Select::new()
                .with_prompt("Presence")
                .items(pr_items)
                .default(0)
                .interact_opt()?;
            match pr_sel {
                Some(0) => {
                    cmd_presence::cmd_presence(cli::PresenceAction::Status, out)?;
                }
                Some(1) => {
                    cmd_presence::cmd_presence(cli::PresenceAction::Start, out)?;
                }
                Some(2) => {
                    cmd_presence::cmd_presence(cli::PresenceAction::Stop, out)?;
                }
                _ => {}
            }
        }
        Some(8) => {
            cmd_config::cmd_config(cli::ConfigAction::Show)?;
        }
        _ => {} // Quit or Esc
    }

    Ok(())
}
