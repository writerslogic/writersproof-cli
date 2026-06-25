// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "writersproof-cli",
    bin_name = "writersproof-cli",
    author,
    version,
    about = "WritersProof — cryptographic proof-of-process authorship witnessing",
    long_about = "WritersProof captures behavioral evidence during document creation and packages \
it into cryptographically signed packets that prove a human authored content over \
time. This provides an offline-verifiable alternative to AI detection by proving \
how something was written, not just what was written."
)]
#[command(after_help = "\
EXAMPLES:\n  \
    writersproof-cli essay.txt                       Start tracking a file\n  \
    writersproof-cli commit essay.txt -m \"Draft 1\"    Create a checkpoint\n  \
    writersproof-cli export essay.txt -t standard     Export evidence (JSON)\n  \
    writersproof-cli export essay.txt -f pdf          Export signed PDF report\n  \
    writersproof-cli export essay.txt --no-beacons    Export without beacon attestation\n  \
    writersproof-cli link essay.txt essay.pdf         Link derivative to source\n  \
    writersproof-cli verify essay.evidence.json       Verify a proof packet\n\n\
ENVIRONMENT:\n  \
    CPOE_DATA_DIR           Override default data directory (~/.writersproof)\n  \
    CPOE_BEACONS_ENABLED    Enable/disable temporal beacons (true/false)\n  \
    EDITOR                  Editor for 'writersproof-cli config edit'\n\n\
Use 'writersproof-cli <command> --help' for details on specific commands.")]
#[command(args_conflicts_with_subcommands = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Path to file, folder, or project to track
    pub path: Option<PathBuf>,

    /// Output results as JSON
    #[arg(long, global = true)]
    pub json: bool,

    /// Suppress informational output
    #[arg(short, long, global = true)]
    pub quiet: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize CPoE environment
    #[command(hide = true)]
    Init {},

    /// Create a cryptographic checkpoint of a document
    #[command(
        alias = "checkpoint",
        after_help = "Checkpoints are chained hashes with VDF time proofs that form \
                      an unforgeable timeline of your writing process."
    )]
    Commit {
        /// Document to checkpoint (omit for interactive selection)
        file: Option<PathBuf>,
        /// Optional message/description
        #[arg(short, long)]
        message: Option<String>,
        /// Anchor evidence in transparency log
        #[arg(long)]
        anchor: bool,
    },

    /// View checkpoint history
    #[command(alias = "history", alias = "ls")]
    Log {
        /// Document to show history for (omit to list all)
        file: Option<PathBuf>,
    },

    /// Export evidence packet
    #[command(
        alias = "prove",
        after_help = "TIERS:\n  \
            basic     T1 — VDF proof only (offline)\n  \
            standard  T2 — + keystrokes + timing (recommended)\n  \
            enhanced  T3 — + behavioral analysis + hardware\n  \
            maximum   T4 — + all external anchors + full attestation\n\n\
            FORMATS:\n  \
            json  Machine-readable evidence packet\n  \
            html  Self-contained HTML report (open in browser)\n  \
            pdf   Signed PDF with anti-forgery security features\n  \
            c2pa  C2PA Content Credentials manifest with embedded VC\n  \
            openbadge  Open Badges 3.0 (1EdTech) verifiable credential\n\n\
            BEACONS:\n  \
            Temporal beacons (drand + NIST) are enabled by default via WritersProof.\n  \
            Use --no-beacons to disable (caps security level at T2)."
    )]
    Export {
        /// Document to export
        file: PathBuf,
        /// Evidence tier (basic, standard, enhanced, maximum)
        #[arg(short = 't', long, visible_alias = "tier", default_value = "basic")]
        tier: String,
        /// Output file path (defaults to stdout for JSON)
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
        /// Output format (json, html, pdf, c2pa, openbadge)
        #[arg(short = 'f', long, default_value = "json")]
        format: String,
        /// Disable temporal beacon attestation (caps security level at T2)
        #[arg(long)]
        no_beacons: bool,
        /// Beacon fetch timeout in seconds (1-300)
        #[arg(long, default_value = "5", value_parser = clap::value_parser!(u64).range(1..=300))]
        beacon_timeout: u64,
        /// Publish evidence to WritersProof for public verification at verify.writersproof.com
        #[arg(long)]
        notarize: bool,
    },

    /// Render the authorship badge (SVG) for an Open Badge credential
    Badge {
        /// Open Badge credential (.openbadge.json) to render the badge for
        #[arg(short, long)]
        credential: PathBuf,
        /// Write the SVG here instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify an evidence packet or database
    #[command(alias = "check")]
    Verify {
        /// Evidence file (.json, .cpoe, .cwar, or .db)
        file: PathBuf,
        /// Public key file to verify against (optional)
        #[arg(short, long)]
        key: Option<PathBuf>,
        /// Write WAR appraisal result to disk
        #[arg(long)]
        output_war: Option<PathBuf>,
    },

    /// Interactive presence challenges
    Presence {
        #[command(subcommand)]
        action: PresenceAction,
    },

    /// Link an export/derivative to a tracked source document
    #[command(
        after_help = "Creates a cryptographic binding between a source document's evidence \
                      chain and an exported derivative (PDF, EPUB, DOCX, etc.).\n\n\
                      EXAMPLES:\n  \
                          cpoe link novel.scriv manuscript.pdf -m \"Final PDF\"\n  \
                          cpoe link essay.txt essay.pdf\n  \
                          cpoe link project.scriv manuscript.epub -m \"EPUB export\""
    )]
    Link {
        /// Source document (the tracked file or project)
        source: PathBuf,
        /// Export or derivative file (PDF, EPUB, DOCX, etc.)
        export: PathBuf,
        /// Description of the relationship
        #[arg(short, long)]
        message: Option<String>,
    },

    /// Track activity on a file or project
    #[command(args_conflicts_with_subcommands = true)]
    Track {
        #[command(subcommand)]
        action: Option<TrackAction>,
        /// Path to track (shorthand for track start)
        file: Option<PathBuf>,
    },

    /// Re-calibrate VDF speed
    #[command(hide = true)]
    Calibrate,

    /// Show current status
    Status,

    /// Generate shell completions
    #[command(hide = true)]
    Completions {
        /// Shell type
        shell: clap_complete::Shell,
    },

    /// Start background daemon
    #[command(hide = true)]
    Start {
        /// Run in foreground
        #[arg(short, long)]
        foreground: bool,
    },

    /// Stop background daemon
    #[command(hide = true)]
    Stop,

    /// Manage behavioral fingerprints
    #[command(alias = "fp")]
    Fingerprint {
        #[command(subcommand)]
        action: FingerprintAction,
    },

    /// Ephemeral text attestation
    #[command(hide = true)]
    Attest {
        /// Output format (war, json)
        #[arg(short, long, default_value = "war")]
        format: String,
        /// Input file (reads stdin if omitted)
        #[arg(short, long)]
        input: Option<PathBuf>,
        /// Output file (writes stdout if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Non-interactive mode
        #[arg(long)]
        non_interactive: bool,
    },

    /// Show or recover your identity
    #[command(alias = "id")]
    Identity {
        /// Show public key fingerprint
        #[arg(long)]
        fingerprint: bool,
        /// Show Decentralized Identifier
        #[arg(long)]
        did: bool,
        /// Show recovery mnemonic (KEEP SECRET)
        #[arg(long)]
        mnemonic: bool,
        /// Recover from mnemonic (reads stdin)
        #[arg(long)]
        recover: bool,
    },

    /// Manage configuration
    #[command(alias = "cfg")]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Detailed forensic analysis
    Forensics {
        #[command(subcommand)]
        action: ForensicsAction,
    },

    /// Temporal beacon attestation
    Beacon {
        #[command(subcommand)]
        action: BeaconAction,
    },

    /// Generate WAR (Written Authorship Report)
    Report {
        /// Document to report on
        file: PathBuf,
        /// Output format (html, json)
        #[arg(short = 'f', long, default_value = "json")]
        format: String,
    },

    /// Manage document snapshots
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },

    /// Manage authorship credentials
    Credential {
        #[command(subcommand)]
        action: CredentialAction,
    },

    /// Display the user manual
    #[command(alias = "manual")]
    Man,
}

impl Commands {
    /// Whether this command requires the sentinel daemon to be running.
    ///
    /// Commands that manage daemon lifecycle, query config, or produce shell
    /// completions do not need auto-start.
    pub fn needs_auto_start(&self) -> bool {
        !matches!(
            self,
            Commands::Start { .. }
                | Commands::Stop
                | Commands::Status
                | Commands::Init { .. }
                | Commands::Calibrate
                | Commands::Config { .. }
                | Commands::Completions { .. }
                | Commands::Badge { .. }
                | Commands::Man
        )
    }
}

#[derive(Subcommand)]
pub enum PresenceAction {
    /// Start a presence verification session
    Start,
    /// End the current presence session and save results
    Stop,
    /// Show current session state and challenge history
    Status,
    /// Answer the current pending presence challenge
    Challenge,
}

#[derive(Subcommand)]
pub enum TrackAction {
    /// Start tracking keystrokes on a file, folder, or project
    Start {
        /// File, folder, or writing app project (.scriv, .textbundle)
        path: PathBuf,
        /// Glob patterns to filter files (e.g. "*.txt,*.md") — directory mode only
        #[arg(short, long, default_value_t = String::new(), hide_default_value = true)]
        patterns: String,
    },
    /// Stop the active tracking session and save results
    Stop,
    /// Show active tracking session status
    Status,
    /// List all saved tracking sessions
    List,
    /// Show details of a saved tracking session
    Show {
        /// Session ID to display
        id: String,
    },
    /// Export evidence from a saved tracking session
    Export {
        /// Session ID to export
        session_id: String,
    },
}

#[derive(Subcommand)]
pub enum FingerprintAction {
    /// Show fingerprint collection status and statistics
    Status,
    /// Display a fingerprint profile
    Show {
        /// Fingerprint ID to display (omit for current profile)
        #[arg(short, long)]
        id: Option<String>,
    },
    /// Compare two fingerprint profiles for similarity
    Compare {
        /// First fingerprint ID
        id1: String,
        /// Second fingerprint ID
        id2: String,
    },
    /// List all stored fingerprint profiles
    List,
    /// Delete a stored fingerprint profile
    Delete {
        /// Fingerprint ID to delete
        id: String,
        /// Skip confirmation prompt
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Show all configuration settings
    Show,
    /// Set a configuration key to a new value
    Set {
        /// Dotted key path (e.g. "sentinel.auto_start")
        key: String,
        /// New value
        value: String,
    },
    /// Open configuration file in $EDITOR
    Edit,
    /// Reset configuration to defaults
    Reset {
        /// Skip confirmation prompt
        #[arg(short, long)]
        force: bool,
    },
    /// Manage monitored writing applications
    App {
        #[command(subcommand)]
        action: AppAction,
    },
}

#[derive(Subcommand)]
pub enum AppAction {
    /// Add a writing application to monitor
    Add {
        /// App name or bundle ID (omit for interactive picker)
        name: Option<String>,
    },
    /// List all monitored apps (built-in and user-added)
    List,
    /// Remove a user-added app
    Remove {
        /// Display name or bundle ID
        name: String,
    },
}

#[derive(Subcommand)]
pub enum ForensicsAction {
    /// Detailed forensic breakdown (timing, behavioral, anomalies)
    Breakdown {
        /// Document to analyze
        path: PathBuf,
    },
    /// Compute process score (residency, sequence, behavioral)
    Score {
        /// Document to score
        path: PathBuf,
    },
    /// Provenance metrics (composition origin, source trust)
    Provenance {
        /// Document to analyze
        path: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum BeaconAction {
    /// Submit a temporal beacon for a document
    Submit {
        /// Document to anchor
        path: PathBuf,
        /// Beacon fetch timeout in seconds
        #[arg(long, default_value = "5", value_parser = clap::value_parser!(u64).range(1..=300))]
        timeout: u64,
    },
    /// Check beacon status for a document
    Status {
        /// Document to check
        path: PathBuf,
    },
    /// List all beacons for a document
    List {
        /// Document to list beacons for
        path: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum SnapshotAction {
    /// Save a document snapshot
    Save {
        /// Document to snapshot
        path: PathBuf,
    },
    /// List snapshots for a document
    List {
        /// Document to list snapshots for
        path: PathBuf,
    },
    /// Get snapshot content by ID
    Get {
        /// Snapshot ID
        id: i64,
    },
    /// Diff a snapshot against the current document
    Diff {
        /// Snapshot ID to diff
        id: i64,
        /// Current document path
        path: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum CredentialAction {
    /// Create an authorship credential from a tracked session
    Create {
        /// Document path
        path: PathBuf,
        /// Session ID (from 'cpoe track show')
        #[arg(long)]
        session: String,
    },
    /// Verify a credential file (hex-encoded CBOR)
    Verify {
        /// Credential file to verify
        file: PathBuf,
    },
    /// Show device attestation info
    Info,
}
