# WritersProof macOS App Guide

The WritersProof macOS app provides a graphical interface for cryptographic authorship witnessing. It runs as a menu bar application with an optional detachable popover dashboard.

## Requirements

- macOS 13.0 (Ventura) or later
- Apple Silicon or Intel processor
- 50 MB disk space

## Installation

1. Download `WritersProof.dmg` from the [releases page](https://github.com/writerslogic/cpoe/releases)
2. Open the DMG and drag **WritersProof** to Applications
3. Launch from Applications or Spotlight

## First Launch

### Onboarding

On first launch:
1. **Welcome** — Overview of features
2. **Permissions** — Grant Accessibility and Input Monitoring permissions
3. **Initialize** — Creates your cryptographic identity and signing keys
4. **Calibrate** — Measures VDF performance for your Mac

### Required Permissions

WritersProof requires these macOS permissions:

| Permission | Purpose |
|------------|---------|
| Accessibility | Count keystroke events (not content) |
| Input Monitoring | Capture timing jitter from hardware input |
| Notifications | Show tracking and checkpoint alerts |

To grant: **System Settings > Privacy & Security > Accessibility** (and Input Monitoring). Enable WritersProof.

**Privacy:** WritersProof only counts keystroke events. It does NOT record which keys you press.

## Menu Bar Interface

### Status Icon

| State | Meaning |
|-------|---------|
| Green (filled) | Actively witnessing |
| Gray | Ready (not witnessing) |
| Light gray (slash) | Not initialized |

### Dashboard Popover

Click the menu bar icon to open the bento-grid dashboard showing:

- **Hero gauge** — Real-time authorship score (0-100%)
- **Session stats** — Keys, WPM, edits, evidence count
- **Typing rhythm** — Live cadence visualization
- **Checkpoint count** — Total checkpoints this session
- **Timer** — Active session duration

The popover can be torn off into a floating window and snapped back to the menu bar.

## Witnessing

### Automatic Detection

WritersProof automatically detects when you open supported writing applications (TextEdit, Pages, Word, Scrivener, VS Code, and 25+ others). Witnessing begins automatically when the app is running.

### What Gets Captured

| Data | Description |
|------|-------------|
| Keystroke count | Total key presses (not which keys) |
| Timing jitter | Nanosecond-precision timing variations |
| Focus events | App switches and document changes |
| Mouse dynamics | Movement patterns and click timing |
| Edit operations | Insertions, deletions, pastes |
| Session duration | Start and end times |

**Not captured:** Key content, clipboard text, screen content, or document text.

### Creating Checkpoints

Checkpoints are created automatically at configured intervals. You can also trigger one manually from the dashboard or menu.

Each checkpoint includes:
- Content hash of the tracked document
- VDF timing proof
- Keystroke count and jitter samples
- Forensic score snapshot

### Exporting Evidence

1. Open the dashboard
2. Select a document session
3. Click **Export Evidence**
4. Choose format (HTML report, PDF, JSON, CBOR) and save location

## Settings

Access via menu bar > **Settings** or **Cmd+,**.

### General
- **Open at Login** — Auto-start on login
- **Auto-checkpoint interval** — Time between automatic checkpoints
- **Debounce interval** — Wait after last keystroke (100-2000ms)

### Monitored Apps
- Configure which applications trigger witnessing
- Add/remove from the allowed/blocked lists

### File Patterns
- Filter which file types to track
- Presets: Text, Documents, Code

### Security
- View signing key fingerprint
- Recalibrate VDF timing
- Toggle hardware attestation (Secure Enclave)

### Notifications
- Enable/disable checkpoint and session notifications

### Advanced
- Data location: `~/Library/Application Support/WritersProof/`
- Default export format and tier
- Reset (deletes all data and keys)

## Data Storage

All data is stored locally:

```
~/Library/Application Support/WritersProof/
  config.toml          # Configuration
  events.db            # Checkpoint database (tamper-evident)
  signing_key          # Private key (protected, mode 0600)
  signing_key.pub      # Public key
  sentinel/            # Sentinel daemon state
  fingerprints/        # Behavioral typing profiles
```

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Cmd+, | Open Settings |
| Cmd+Q | Quit WritersProof |

## Troubleshooting

### Menu Bar Icon Missing
1. Check if app is running in Activity Monitor
2. Check menu bar overflow (click `>>` on right side)
3. Restart the app

### Keystroke Counting Not Working
1. Verify Accessibility AND Input Monitoring permissions are granted
2. Toggle permissions off and on
3. Restart the app after granting permissions

### VDF Not Calibrated
Open Settings > Security > click **Recalibrate VDF** (~30 seconds).

### High CPU Usage
Brief spikes during VDF computation are normal. If sustained:
- Reduce checkpoint frequency in Settings
- Increase debounce interval

See also: [Troubleshooting Guide](troubleshooting.md) | [CLI Reference](cli-reference.md)
