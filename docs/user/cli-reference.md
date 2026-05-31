# CLI Reference

Complete reference for the `cpoe` command-line interface.

## Synopsis

```
cpoe [command] [options] [arguments]
cpoe <file>                         # Start tracking a file (shorthand)
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
cpoe init
```

Safe to run multiple times (idempotent). Run `cpoe calibrate` after first initialization.

---

#### commit

Create a cryptographic checkpoint. Alias: `checkpoint`.

```bash
cpoe commit <file> [-m <message>] [--anchor]
```

| Option | Description |
|--------|-------------|
| `-m <message>` | Checkpoint description |
| `--anchor` | Anchor evidence in transparency log |

---

#### log

View checkpoint history. Aliases: `history`, `ls`.

```bash
cpoe log [file]
```

Without a file argument, lists all tracked files.

---

#### export

Export evidence packet with declaration. Alias: `prove`.

```bash
cpoe export <file> [options]
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
cpoe verify <file> [-k <key>] [--output-war <path>]
```

| Option | Description |
|--------|-------------|
| `-k <key>` | Public key file (optional) |
| `--output-war <path>` | Write WAR appraisal result to disk |

Accepts `.json`, `.c2pa` packets or `.db` files.

---

#### status

Show current tracking status and configuration.

```bash
cpoe status
```

### Document Management

#### track

Track activity on a file or project.

```bash
cpoe track start <path> [--patterns <globs>]
cpoe track stop
cpoe track status
cpoe track list
cpoe track show <id>
cpoe track export <session_id>
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
cpoe link <source> <export> [-m <message>]
```

Creates a cryptographic binding between the source evidence chain and a derivative (PDF, EPUB, DOCX).

---

#### snapshot

Manage document snapshots.

```bash
cpoe snapshot save <path>
cpoe snapshot list <path>
cpoe snapshot get <id>
cpoe snapshot diff <id> <path>
```

### Identity and Security

#### identity

Show or recover your cryptographic identity. Alias: `id`.

```bash
cpoe identity [options]
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
cpoe fingerprint status
cpoe fingerprint show [--id <id>]
cpoe fingerprint compare <id1> <id2>
cpoe fingerprint list
cpoe fingerprint delete [--force]
```

---

#### credential

Manage authorship credentials and verifiable presentations.

```bash
cpoe credential create <path> [--session <id>]
cpoe credential verify <file>
cpoe credential info
```

### Analysis and Reporting

#### forensics

Detailed forensic analysis of writing sessions.

```bash
cpoe forensics breakdown <path>
cpoe forensics score <path>
cpoe forensics provenance <path>
```

---

#### report

Generate a Written Authorship Report (WAR).

```bash
cpoe report <file> [-f <format>]
```

| Option | Description |
|--------|-------------|
| `-f <format>` | Format: html, json (default: json) |

---

#### beacon

Temporal beacon attestation.

```bash
cpoe beacon submit <path> [--timeout <secs>]
cpoe beacon status <path>
cpoe beacon list <path>
```

### Configuration

#### config

Manage configuration. Alias: `cfg`.

```bash
cpoe config show
cpoe config set <key> <value>
cpoe config edit
cpoe config reset [--force]
cpoe config path
cpoe config app add <name>
cpoe config app list
cpoe config app remove <name>
```

---

#### calibrate

Re-calibrate VDF performance for this machine.

```bash
cpoe calibrate
```

Takes ~30 seconds. Only needed once per machine.

### Presence Verification

#### presence

Interactive presence challenges.

```bash
cpoe presence start
cpoe presence stop
cpoe presence status
cpoe presence challenge
```

### Utility

#### completions

Generate shell completions.

```bash
cpoe completions <shell>
```

Shells: bash, zsh, fish, powershell, elvish.

---

#### man

Display the user manual. Alias: `manual`.

```bash
cpoe man
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
cpoe essay.txt                              # Start tracking
# ... write your document ...
cpoe commit essay.txt -m "first draft"      # Create checkpoint
# ... continue writing ...
cpoe commit essay.txt -m "revisions"        # More checkpoints
cpoe export essay.txt -t standard           # Export evidence
cpoe verify evidence.json                   # Verify evidence
```

## Enhanced Workflow

For strongest evidence with keystroke tracking and PDF reports:

```bash
cpoe track start paper.tex
# ... write for several hours ...
cpoe commit paper.tex -m "Final version"
cpoe track stop
cpoe export paper.tex -t enhanced -f pdf -o paper-proof.pdf
cpoe link paper.tex paper.pdf -m "Published PDF"
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
| `EDITOR` | Editor for `cpoe config edit` |

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
