# Configuration Guide

CPoE can be configured through a TOML configuration file, environment variables, and command-line flags.

## Configuration File Location

| Platform | Path |
|----------|------|
| CLI (all platforms) | `~/.writersproof/config.toml` |
| macOS App | `~/Library/Application Support/WritersProof/config.toml` |

Override with:
```bash
CPOE_DATA_DIR=/custom/path cpoe status
```

## Configuration File Format

CPoE uses TOML configuration:

```toml
data_dir = "~/.writersproof"
watch_dirs = ["~/Documents"]
retention_days = 30

[vdf]
iterations_per_second = 1000000
min_iterations = 100000
max_iterations = 3600000000

[sentinel]
auto_start = false
heartbeat_interval_secs = 60
checkpoint_interval_secs = 60
idle_timeout_secs = 1800

[beacons]
enabled = true
timeout_secs = 5
retries = 2

[presence]
challenge_interval_secs = 600
response_window_secs = 60

[fingerprint]
activity_enabled = true
style_enabled = false
retention_days = 365
min_samples = 100
bootstrap_sessions = 5

[privacy]
detect_sensitive_fields = true
hash_urls = true
obfuscate_titles = true

[writersproof]
enabled = false
auto_attest = false
offline_queue = true

[trust_bundle]
max_cache_age_secs = 86400
fetch_timeout_secs = 10
```

## VDF Settings

The Verifiable Delay Function provides timing proofs that cannot be backdated.

| Key | Default | Description |
|-----|---------|-------------|
| `iterations_per_second` | `1000000` | Calibrated speed (run `cpoe calibrate`) |
| `min_iterations` | `100000` | Minimum iterations per checkpoint (~0.1s) |
| `max_iterations` | `3600000000` | Maximum iterations (~1 hour at 1M/s) |

Run `cpoe calibrate` after installation to measure your CPU's actual VDF speed. This takes ~30 seconds and only needs to be done once.

## Sentinel Settings

The sentinel daemon monitors writing activity and creates automatic checkpoints.

| Key | Default | Description |
|-----|---------|-------------|
| `auto_start` | `false` | Start sentinel on init |
| `heartbeat_interval_secs` | `60` | Heartbeat frequency |
| `checkpoint_interval_secs` | `60` | Auto-checkpoint interval |
| `idle_timeout_secs` | `1800` | Stop session after 30min idle |
| `idle_check_interval_secs` | `60` | How often to check for idle |
| `focus_debounce_ms` | `150` | Suppress transient focus bounces |
| `hash_on_focus` | `true` | Hash document on focus change |
| `hash_on_save` | `true` | Hash document on save |
| `recursive_watch` | `true` | Watch subdirectories |
| `track_unknown_apps` | `true` | Track apps not in allowed_apps |
| `snapshots_enabled` | `false` | Save document snapshots |
| `require_hardware_attestation` | `false` | Require TPM/SE for sessions |

### App Filtering

```toml
[sentinel]
# Only track these apps (empty = track all unless blocked)
allowed_apps = []

# Never track these apps
blocked_apps = ["Finder", "Explorer", "Spotlight", "Notification Center"]

# Only track files with these extensions
allowed_extensions = ["txt", "md", "docx", "rtf", "scriv", "tex", "org"]

# Never track files in these paths
excluded_paths = ["/tmp", "/var", "node_modules", ".git", "build", "dist"]
```

## Beacon Settings

Temporal beacons anchor evidence to publicly verifiable time sources (drand, NIST, Roughtime).

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Enable beacon attestation |
| `timeout_secs` | `5` | Fetch timeout (1-300) |
| `retries` | `2` | Retry attempts (0-10) |

```toml
[beacons.roughtime]
enabled = true
tolerance_secs = 0    # 0 = auto-calibrate
servers = []          # empty = use built-in defaults
```

Disabling beacons caps evidence security level at T2.

## Fingerprint Settings

Behavioral typing fingerprints provide author identity verification.

| Key | Default | Description |
|-----|---------|-------------|
| `activity_enabled` | `true` | Collect keystroke dynamics |
| `style_enabled` | `false` | Collect writing style metrics |
| `retention_days` | `365` | How long to keep fingerprint data |
| `min_samples` | `100` | Minimum keystrokes before fingerprint is usable |
| `bootstrap_sessions` | `5` | Sessions before anomaly detection activates |
| `advisory_sessions` | `10` | Sessions before anomalies block |

## Privacy Settings

| Key | Default | Description |
|-----|---------|-------------|
| `detect_sensitive_fields` | `true` | Detect and exclude sensitive content |
| `hash_urls` | `true` | Hash URLs in metadata |
| `obfuscate_titles` | `true` | Obfuscate window titles in evidence |
| `excluded_apps` | `["1Password", "Keychain Access", "Terminal"]` | Never monitor these |

## WritersProof API Settings

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `false` | Enable WritersProof API integration |
| `auto_attest` | `false` | Auto-submit attestation on export |
| `offline_queue` | `true` | Queue attestations when offline |

## Trust Bundle Settings

| Key | Default | Description |
|-----|---------|-------------|
| `max_cache_age_secs` | `86400` | Cache CA bundle for 24 hours |
| `fetch_timeout_secs` | `10` | Bundle fetch timeout (1-60) |

## Presence Settings

| Key | Default | Description |
|-----|---------|-------------|
| `challenge_interval_secs` | `600` | Time between presence challenges |
| `response_window_secs` | `60` | Time to respond to challenge |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CPOE_DATA_DIR` | Override data directory (~/.writersproof) |
| `CPOE_BEACONS_ENABLED` | Override beacon setting (true/false) |
| `EDITOR` | Editor for `cpoe config edit` |

## CLI Configuration Commands

```bash
# Show current configuration
cpoe config show

# Edit configuration in $EDITOR
cpoe config edit

# Set a specific value
cpoe config set sentinel.checkpoint_interval_secs 120

# Reset to defaults
cpoe config reset --force

# Show config file path
cpoe config path

# Manage monitored apps
cpoe config app add "Scrivener"
cpoe config app list
cpoe config app remove "TextEdit"
```

## Configuration Examples

### Writer (automatic, low-friction)

```toml
[sentinel]
auto_start = true
checkpoint_interval_secs = 300
idle_timeout_secs = 3600
allowed_extensions = ["md", "txt", "rtf", "docx", "scriv", "tex"]

[beacons]
enabled = true

[fingerprint]
activity_enabled = true
```

### High-Security (legal/compliance)

```toml
[vdf]
min_iterations = 1000000

[sentinel]
auto_start = true
heartbeat_interval_secs = 30
checkpoint_interval_secs = 60
require_hardware_attestation = true

[presence]
challenge_interval_secs = 300
response_window_secs = 30

[beacons]
enabled = true
timeout_secs = 10
retries = 3

[writersproof]
enabled = true
auto_attest = true
```

### Development/Testing

```toml
[vdf]
min_iterations = 1000
max_iterations = 10000

[sentinel]
checkpoint_interval_secs = 10
idle_timeout_secs = 300

[beacons]
enabled = false
```

---

See also:
- [CLI Reference](cli-reference.md) for command-line options
- [Getting Started](getting-started.md) for initial setup
- [Troubleshooting](troubleshooting.md) for common issues
