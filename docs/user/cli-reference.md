# CLI Reference

Complete reference for the `cpoe` command-line interface.

## Synopsis

```
writersproof-cli [command] [options] [arguments]
writersproof-cli <file>                         # Start tracking a file (shorthand)
```

## Global Options

| Option | Description |
|--------|-------------|
| `--json` | Output results as JSON |
| `-q`, `--quiet` | Suppress informational output |
| `-h`, `--help` | Show help for command |

## Security Levels

Each evidence export is assigned a security level based on available temporal witnesses:

| Level | Name | Description |
|-------|------|-------------|
| T1 | Basic | VDF proof only (offline) |
| T2 | Standard | + keystrokes + timing |
| T3 | Enhanced | + behavioral analysis + hardware attestation |
| T4 | Maximum | + all external anchors + full attestation |

## Commands

### Core Workflow

#### init

Initialize CPoE environment (keys, database, configuration).

```bash
writersproof-cli init
```

Safe to run multiple times (idempotent). Run `writersproof-cli calibrate` after first initialization.

---

#### commit

Create a cryptographic checkpoint. Alias: `checkpoint`.

```bash
writersproof-cli commit <file> [-m <message>] [--anchor]
```

| Option | Description |
|--------|-------------|
| `-m <message>` | Checkpoint description |
| `--anchor` | Anchor evidence in transparency log |

---

#### log

View checkpoint history. Aliases: `history`, `ls`.

```bash
writersproof-cli log [file]
```

Without a file argument, lists all tracked files.

---

#### export

Export evidence packet with declaration. Alias: `prove`.

```bash
writersproof-cli export <file> [options]
```

| Option | Description |
|--------|-------------|
| `-o <path>` | Output file path |
| `-f <format>` | Format: json, c2pa, html, pdf |
| `-t <tier>` | Tier: basic, standard, enhanced, maximum |
| `--no-beacons` | Disable temporal beacons (caps at T2) |
| `--beacon-timeout <secs>` | Beacon fetch timeout (default: 5) |

**Formats:**
- `json` — Human-readable evidence packet
- `c2pa` — C2PA Content Credentials manifest with embedded VC
- `html` — Self-contained HTML report
- `pdf` — Signed PDF with anti-forgery security features

---

#### verify

Verify an evidence packet or database. Alias: `check`.

```bash
writersproof-cli verify <file> [-k <key>] [--output-war <path>]
```

| Option | Description |
|--------|-------------|
| `-k <key>` | Public key file (optional) |
| `--output-war <path>` | Write WAR appraisal result to disk |

Accepts `.json`, `.c2pa`, `.cpoe`, `.cwar` packets or `.db` files.

---

#### status

Show current tracking status and configuration.

```bash
writersproof-cli status
```

### Document Management

#### track

Track activity on a file or project.

```bash
writersproof-cli track start <path> [--patterns <globs>]
writersproof-cli track stop
writersproof-cli track status
writersproof-cli track list
writersproof-cli track show <id>
writersproof-cli track export <session_id>
```

| Action | Description |
|--------|-------------|
| `start <path>` | Start tracking (file or directory) |
| `stop` | End current tracking session |
| `status` | Show active tracking |
| `list` | List all tracking sessions |
| `show <id>` | Show session details |
| `export <id>` | Export session data |

The `--patterns` flag accepts glob filters for directory-mode tracking.

---

#### link

Link an export/derivative to a tracked source document.

```bash
writersproof-cli link <source> <export> [-m <message>]
```

Creates a cryptographic binding between the source evidence chain and a derivative (PDF, EPUB, DOCX).

---

#### snapshot

Manage document snapshots.

```bash
writersproof-cli snapshot save <path>
writersproof-cli snapshot list <path>
writersproof-cli snapshot get <id>
writersproof-cli snapshot diff <id> <path>
```

### Identity and Security

#### identity

Show or recover your cryptographic identity. Alias: `id`.

```bash
writersproof-cli identity [options]
```

| Option | Description |
|--------|-------------|
| `--fingerprint` | Show public key fingerprint |
| `--did` | Show Decentralized Identifier |
| `--mnemonic` | Show BIP-39 recovery mnemonic |
| `--recover` | Recover identity from mnemonic |

---

#### fingerprint

Manage behavioral typing fingerprints. Alias: `fp`.

```bash
writersproof-cli fingerprint status
writersproof-cli fingerprint show [--id <id>]
writersproof-cli fingerprint compare <id1> <id2>
writersproof-cli fingerprint list
writersproof-cli fingerprint delete <id> [--force]
```

---

#### credential

Manage authorship credentials.

```bash
writersproof-cli credential create <path> --session <id>
writersproof-cli credential verify <file>
writersproof-cli credential info
```

### Analysis and Reporting

#### forensics

Detailed forensic analysis of writing sessions.

```bash
writersproof-cli forensics breakdown <path>
writersproof-cli forensics score <path>
writersproof-cli forensics provenance <path>
```

---

#### report

Generate a Written Authorship Report (WAR).

```bash
writersproof-cli report <file> [-f <format>]
```

| Option | Description |
|--------|-------------|
| `-f <format>` | Format: html, json (default: json) |

---

#### beacon

Temporal beacon attestation.

```bash
writersproof-cli beacon submit <path> [--timeout <secs>]
writersproof-cli beacon status <path>
writersproof-cli beacon list <path>
```

#### attest

One-shot text attestation via ephemeral sessions.

```bash
writersproof-cli attest [-f <format>] [-i <input>] [-o <output>] [--non-interactive]
```

| Option | Description |
|--------|-------------|
| `-f <format>` | Output format (default: json) |
| `-i <input>` | Input file (reads from stdin if omitted) |
| `-o <output>` | Output file (writes to stdout if omitted) |
| `--non-interactive` | Skip interactive prompts |

---

### Daemon Management

#### start

Start the sentinel daemon.

```bash
writersproof-cli start [--foreground]
```

| Option | Description |
|--------|-------------|
| `--foreground` | Run in foreground instead of daemonizing |

---

#### stop

Stop the sentinel daemon.

```bash
writersproof-cli stop
```

---

### Configuration

#### config

Manage configuration. Alias: `cfg`.

```bash
writersproof-cli config show
writersproof-cli config set <key> <value>
writersproof-cli config edit
writersproof-cli config reset [--force]
writersproof-cli config app add [<name>]
writersproof-cli config app list
writersproof-cli config app remove <name>
```

---

#### calibrate

Re-calibrate VDF performance for this machine.

```bash
writersproof-cli calibrate
```

Takes ~30 seconds. Only needed once per machine.

### Presence Verification

#### presence

Interactive presence challenges.

```bash
writersproof-cli presence start
writersproof-cli presence stop
writersproof-cli presence status
writersproof-cli presence challenge
```

### Utility

#### completions

Generate shell completions.

```bash
writersproof-cli completions <shell>
```

Shells: bash, zsh, fish, powershell, elvish.

---

#### man

Display the user manual. Alias: `manual`.

```bash
writersproof-cli man
```

## Evidence Tiers

Per `draft-condrey-rats-pop`:

| Tier | Name | Description |
|------|------|-------------|
| basic (T1) | Basic | VDF proof only (offline) |
| standard (T2) | Standard | + keystrokes + timing (recommended) |
| enhanced (T3) | Enhanced | + behavioral analysis + hardware attestation |
| maximum (T4) | Maximum | + all external anchors + full attestation |

## Basic Workflow

```bash
writersproof-cli essay.txt                              # Start tracking
# ... write your document ...
writersproof-cli commit essay.txt -m "first draft"      # Create checkpoint
# ... continue writing ...
writersproof-cli commit essay.txt -m "revisions"        # More checkpoints
writersproof-cli export essay.txt -t standard           # Export evidence
writersproof-cli verify evidence.json                   # Verify evidence
```

## Enhanced Workflow

For strongest evidence with keystroke tracking and PDF reports:

```bash
writersproof-cli track start paper.tex
# ... write for several hours ...
writersproof-cli commit paper.tex -m "Final version"
writersproof-cli track stop
writersproof-cli export paper.tex -t enhanced -f pdf -o paper-proof.pdf
writersproof-cli link paper.tex paper.pdf -m "Published PDF"
```

## Files

| Path | Description |
|------|-------------|
| `~/.writersproof/` | Main data directory |
| `~/.writersproof/config.toml` | Configuration file |
| `~/.writersproof/signing_key` | Ed25519 private key (mode 0600) |
| `~/.writersproof/signing_key.pub` | Ed25519 public key |
| `~/.writersproof/chains/` | Checkpoint chains |
| `~/.writersproof/sessions/` | Presence verification sessions |
| `~/.writersproof/tracking/` | Keystroke tracking sessions |
| `~/.writersproof/fingerprints/` | Behavioral typing profiles |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CPOE_DATA_DIR` | Override data directory |
| `CPOE_BEACONS_ENABLED` | Enable/disable beacons (true/false) |
| `EDITOR` | Editor for `writersproof-cli config edit` |

## Privacy

Keystroke tracking counts keystrokes but does NOT capture which keys are pressed. This is NOT a keylogger. Only event counts, inter-key intervals, and timing jitter are recorded. Content is never stored.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error occurred |

---

See also:
- [Getting Started](getting-started.md) for initial setup
- [Configuration](configuration.md) for all config options
- [Troubleshooting](troubleshooting.md) for common issues
