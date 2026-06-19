# Troubleshooting Guide

Solutions to common issues with CPoE.

## Installation & Setup

### "Command not found: writersproof-cli"
- **Cause**: CPoE is not in your PATH.
- **Solution**: Ensure `/usr/local/bin` or your custom install directory is in your shell's PATH.

### "Error deriving master identity"
- **Cause**: Hardware identity ([[Glossary#PUF|PUF]]) initialization failed.
- **Solution**: Check file permissions for `~/.writersproof/`. Run `writersproof-cli init` again.

---

## Tracking & Checkpoints

### Keystroke count always zero (macOS)
- **Cause**: Missing Accessibility permissions.
- **Solution**: Go to **System Settings > Privacy & Security > Accessibility** and ensure CPoE is enabled. Restart the application after granting permissions.

### Checkpoint failed: HMAC verification error
- **Cause**: The database integrity check failed, possibly indicating manual editing of the database.
- **Solution**: CPoE databases are tamper-evident. If you manually modified `events.db`, you must restore from a backup.

### [[Glossary#VDF|VDF]] computation timeout
- **Cause**: Your CPU speed has changed or was never calibrated.
- **Solution**: Run `writersproof-cli calibrate` to update your performance parameters.

---

## Verification

### "Invalid checkpoint chain"
- **Cause**: The cryptographic links between checkpoints are broken.
- **Solution**: Ensure you haven't deleted intermediate checkpoints from your database. Run `writersproof-cli verify <file> --verbose` for more details.

### "VDF proof invalid"
- **Cause**: The timing proof doesn't match the expected iterations.
- **Solution**: This usually occurs if the proof was created on a system with a different VDF version or if the proof data was corrupted.

---

## Data & Recovery

### Lost Signing Key
- **Impact**: You can no longer prove authorship with your old identity.
- **Solution**: There is no "recovery password." Your signing key is your identity. Always keep a secure backup of `~/.writersproof/signing_key`.

### Database Corruption
- **Solution**: You can attempt to recover a corrupted SQLite database using:
  ```bash
  sqlite3 ~/.writersproof/events.db ".recover" | sqlite3 events_recovered.db
  ```

---

*For more help, please open an **[Issue on GitHub](https://github.com/writerslogic/writersproof-cli/issues)**.*
