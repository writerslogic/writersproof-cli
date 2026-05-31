# CLI Reference

The `cpoe` command-line tool is the primary interface for managing authorship evidence.

## Global Options

| Option | Description |
|--------|-------------|
| `--config <path>` | Use custom configuration directory (default: `~/.writerslogic`) |
| `-h`, `--help` | Show help for a command |
| `-v`, `--version` | Show version information |

---

## Core Commands

### `init`
Initialize CPoE and generate your cryptographic identity.
```bash
cpoe init
```

### `calibrate`
Measure your CPU performance for VDF timing proofs. Run this once after installation.
```bash
cpoe calibrate
```

### `commit`
Create a checkpoint for a file.
```bash
cpoe commit <file> [-m "message"]
```

### `log`
Show the checkpoint history for a file.
```bash
cpoe log <file>
```

### `status`
Show the current status of CPoE, including your identity and configuration.
```bash
cpoe status
```

---

## Evidence Commands

### `export`
Export a `.c2pa` evidence packet containing the full chain of authorship proof.
```bash
cpoe export <file> [-o output.c2pa]
```

### `verify`
Verify an evidence packet or a local file's checkpoint chain.
```bash
cpoe verify <file_or_packet>
```

---

## Tracking Commands

### `track`
Manage real-time activity tracking for a document.
```bash
cpoe track start <file>
cpoe track status
cpoe track stop
```

### `sentinel`
Manage the background daemon that handles automatic tracking and checkpoints.
```bash
CPoE sentinel start
CPoE sentinel status
CPoE sentinel stop
```

---

## Additional Commands

- `list`: List all files that have checkpoints in the database.
- `watch`: Automatically checkpoint files in specific folders.
- `presence`: Start a presence verification session (periodic challenges).
- `fingerprint`: Manage behavioral fingerprinting settings.

---

## Interactive Menu

If you run `cpoe` without any arguments, it will launch an interactive TUI menu for easy navigation.

---

*For detailed troubleshooting, see the **[[Troubleshooting]]** guide.*
