# Troubleshooting Guide

Solutions to common issues with CPoE.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Initialization Issues](#initialization-issues)
- [Tracking Issues](#tracking-issues)
- [Checkpoint Issues](#checkpoint-issues)
- [Verification Issues](#verification-issues)
- [Performance Issues](#performance-issues)
- [macOS App Issues](#macos-app-issues)
- [Data Recovery](#data-recovery)
- [Getting Help](#getting-help)

## Installation Issues

### "Command not found: writersproof-cli"

**Cause:** CPoE is not in your PATH.

**Solutions:**

1. **Verify installation:**
   ```bash
   which writerslogic
   ls -la /usr/local/bin/writerslogic
   ```

2. **Add to PATH (if installed elsewhere):**
   ```bash
   export PATH="$PATH:$HOME/.local/bin"
   ```

3. **Reinstall:**
   ```bash
   make install
   # or
   brew reinstall writerslogic
   ```

### Build Fails with Rust Errors

**Cause:** Incompatible Rust version or missing dependencies.

**Solution:**
```bash
# Check Rust version (requires 1.75+)
rustc --version

# Update Rust
rustup update stable

# Clean and rebuild
cargo clean
cargo build --release
```

### Permission Denied During Install

**Cause:** Insufficient permissions for /usr/local/bin.

**Solution:**
```bash
# Option 1: Use sudo
sudo make install

# Option 2: Install to user directory
make install PREFIX=$HOME/.local
```

## Initialization Issues

### "Error creating directory: permission denied"

**Cause:** Cannot create ~/.writersproof directory.

**Solutions:**

1. **Check home directory permissions:**
   ```bash
   ls -la ~/
   ```

2. **Create directory manually:**
   ```bash
   mkdir -p ~/.writersproof
   chmod 700 ~/.writersproof
   writersproof-cli init
   ```

### "Error generating key"

**Cause:** Insufficient entropy or crypto subsystem issue.

**Solutions:**

1. **Check entropy (Linux):**
   ```bash
   cat /proc/sys/kernel/random/entropy_avail
   # Should be > 256
   ```

2. **Regenerate key manually:**
   ```bash
   rm ~/.writersproof/signing_key*
   writersproof-cli init
   ```

### "Error deriving master identity"

**Cause:** PUF initialization failed.

**Solutions:**

1. **Remove PUF seed and reinitialize:**
   ```bash
   rm ~/.writersproof/puf_seed
   writersproof-cli init
   ```

2. **Check file permissions:**
   ```bash
   chmod 600 ~/.writersproof/puf_seed
   ```

## Tracking Issues

### "Tracking not starting"

**Cause:** Various possible causes.

**Solutions:**

1. **Check if CPoE is initialized:**
   ```bash
   writersproof-cli status
   ```

2. **Verify file exists:**
   ```bash
   ls -la /path/to/document.md
   ```

3. **Check for existing tracking session:**
   ```bash
   writersproof-cli track status
   # If stuck, stop and restart
   writersproof-cli track stop
   writersproof-cli track start document.md
   ```

### "Keystroke count always zero"

**Cause:** Accessibility permissions not granted (macOS) or event capture not working.

**Solutions (macOS):**

1. **Grant accessibility permissions:**
   - System Settings > Privacy & Security > Accessibility
   - Enable CPoE

2. **Restart the app after granting permissions**

3. **Check if permissions are actually granted:**
   ```bash
   sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
     "SELECT * FROM access WHERE service='kTCCServiceAccessibility'"
   ```

**Solutions (Linux):**

1. **Check if running in terminal with input:**
   ```bash
   # Must run in terminal that receives keyboard input
   writersproof-cli track start document.md
   ```

2. **Verify input group membership:**
   ```bash
   groups | grep input
   # If not present:
   sudo usermod -a -G input $USER
   # Log out and back in
   ```

### "WAL file corrupted"

**Cause:** System crash during tracking or disk issue.

**Solutions:**

1. **Stop tracking and check WAL:**
   ```bash
   writersproof-cli track stop
   ls -la ~/.writersproof/tracking/
   ```

2. **Remove corrupted WAL:**
   ```bash
   rm ~/.writersproof/tracking/*.wal
   ```

3. **Existing checkpoints are preserved in the database**

## Checkpoint Issues

### "Error opening database"

**Cause:** Database file corrupted or locked.

**Solutions:**

1. **Check database status:**
   ```bash
   sqlite3 ~/.writersproof/events.db "PRAGMA integrity_check;"
   ```

2. **If locked, find process holding lock:**
   ```bash
   lsof ~/.writersproof/events.db
   ```

3. **If corrupted, attempt recovery:**
   ```bash
   sqlite3 ~/.writersproof/events.db ".recover" | sqlite3 events_recovered.db
   mv events_recovered.db ~/.writersproof/events.db
   ```

### "VDF computation timeout"

**Cause:** VDF taking too long, possibly uncalibrated.

**Solutions:**

1. **Calibrate VDF:**
   ```bash
   writersproof-cli calibrate
   ```

2. **Check VDF settings:**
   ```bash
   cat ~/.writersproof/config.toml | grep -A5 '"vdf"'
   ```

3. **Reduce max iterations if needed:**
   ```toml
   [vdf]
   max_iterations = 900000000
   ```

### "Checkpoint failed: HMAC verification error"

**Cause:** Database integrity check failed (possible tampering).

**Solutions:**

1. **This is a security feature - investigate cause**

2. **Check if signing key changed:**
   ```bash
   sha256sum ~/.writersproof/signing_key
   ```

3. **If key was regenerated, previous checkpoints cannot be verified**

## Verification Issues

### "Invalid checkpoint chain"

**Cause:** Checkpoints don't form valid chain.

**Solutions:**

1. **Verify with verbose output:**
   ```bash
   writersproof-cli verify document.md --verbose
   ```

2. **Check for gaps in sequence:**
   ```bash
   writersproof-cli log document.md --json | jq '.[].number'
   ```

### "VDF proof invalid"

**Cause:** VDF proof doesn't verify.

**Solutions:**

1. **Re-verify with current VDF parameters:**
   ```bash
   writersproof-cli calibrate
   writersproof-cli verify document.c2pa
   ```

2. **VDF proofs are deterministic - if fails, evidence may be invalid**

### "Key hierarchy verification failed"

**Cause:** Session certificate or signature invalid.

**Solutions:**

1. **Check certificate chain:**
   ```bash
   writersproof-cli verify document.c2pa --verbose 2>&1 | grep -i cert
   ```

2. **Verify master identity matches:**
   ```bash
   cat ~/.writersproof/identity.json | jq '.fingerprint'
   ```

## Performance Issues

### High CPU Usage

**Cause:** VDF computation or sentinel running.

**Solutions:**

1. **Check what's running:**
   ```bash
   writersproof-cli status
   writersproof-cli track status
   ```

2. **VDF computation is intentionally CPU-intensive (brief)**

3. **Reduce checkpoint frequency:**
   ```toml
   [sentinel]
   checkpoint_interval_secs = 300
   ```

### High Disk Usage

**Cause:** Many checkpoints or large WAL files.

**Solutions:**

1. **Check disk usage:**
   ```bash
   du -sh ~/.writersproof/*
   ```

2. **WAL files can be cleaned after tracking stops:**
   ```bash
   rm ~/.writersproof/tracking/*.wal
   ```

3. **Database compaction:**
   ```bash
   sqlite3 ~/.writersproof/events.db "VACUUM;"
   ```

### Slow Checkpoints

**Cause:** Large file or uncalibrated VDF.

**Solutions:**

1. **Calibrate VDF:**
   ```bash
   writersproof-cli calibrate
   ```

2. **For large files, checkpointing takes longer due to hashing**

3. **Check file size:**
   ```bash
   ls -lh /path/to/document
   ```

## macOS App Issues

### Menu Bar Icon Missing

**Solutions:**

1. **Check if app is running:**
   ```bash
   pgrep -l WritersProof
   ```

2. **Check menu bar overflow** (click >> on right side of menu bar)

3. **Restart the app:**
   ```bash
   pkill WritersProof
   open /Applications/WritersProof.app
   ```

### App Crashes on Launch

**Solutions:**

1. **Check Console for crash logs:**
   - Open Console.app
   - Filter for "WritersProof"

2. **Reset app state:**
   ```bash
   rm -rf ~/Library/Application\ Support/WritersProof/
   open /Applications/WritersProof.app
   ```

3. **Check macOS version compatibility**

### Notifications Not Working

**Solutions:**

1. **Check notification permissions:**
   - System Settings > Notifications > WritersProof

2. **Check Focus mode** isn't blocking notifications

3. **Toggle notifications off and on in app settings**

### Accessibility Permission Issues

**Solutions:**

1. **Remove and re-add permission:**
   - System Settings > Privacy & Security > Accessibility
   - Remove CPoE
   - Quit and relaunch app
   - Grant permission when prompted

2. **Full disk access may be required for some features:**
   - System Settings > Privacy & Security > Full Disk Access

## Data Recovery

### Lost Signing Key

**Impact:** Cannot sign new checkpoints with same identity.

**Solutions:**

1. **Check for backups:**
   ```bash
   ls ~/.writersproof/signing_key*
   ```

2. **If no backup, generate new key:**
   ```bash
   writersproof-cli init
   ```

3. **Previous evidence remains valid but new evidence will have different identity**

### Database Corruption

**Solutions:**

1. **Attempt recovery:**
   ```bash
   cp ~/.writersproof/events.db events.backup
   sqlite3 events.backup ".recover" | sqlite3 events.recovered.db
   ```

2. **Check recovered data:**
   ```bash
   sqlite3 events.recovered.db "SELECT COUNT(*) FROM secure_events;"
   ```

3. **Replace if recovery successful:**
   ```bash
   mv events.recovered.db ~/.writersproof/events.db
   ```

### Export Existing Data

Before complete reset:

```bash
# Export all evidence packets
for file in $(writersproof-cli log --all --files); do
  writersproof-cli export "$file" -o "backup_${file}.c2pa"
done
```

## Getting Help

### Diagnostic Information

Collect this before reporting issues:

```bash
# System info
uname -a
writersproof-cli --version

# Configuration
cat ~/.writersproof/config.toml

# Status
writersproof-cli status

# Recent logs (if available)
tail -100 ~/.writersproof/cpoe.log
```

### Reporting Issues

1. Search [existing issues](https://github.com/writerslogic/writersproof-cli/issues)
2. Create new issue with:
   - CPoE version
   - Operating system and version
   - Steps to reproduce
   - Expected vs actual behavior
   - Diagnostic information

### Community Support

- GitHub Discussions: https://github.com/writerslogic/writersproof-cli/discussions
- Discord: https://discord.gg/writerslogic

---

See also:
- [Getting Started](getting-started.md)
- [Configuration](configuration.md)
- [CLI Reference](cli-reference.md)
