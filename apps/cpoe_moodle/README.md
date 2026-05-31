# WritersProof for Moodle

Cryptographic authorship attestation plugin for Moodle LMS. Captures writing process evidence from student submissions in assignments, forums, and wikis, then ships tamper-evident proof to the WritersProof API.

## How It Works

1. When students submit assignments, forum posts, or wiki edits, the plugin captures content checkpoints
2. Content hashes are computed (never raw content sent externally)
3. Evidence events are shipped to WritersProof for cryptographic witnessing
4. Instructors can verify authorship evidence for student submissions

## Setup

### Prerequisites

- Moodle 4.1+ (version 2022112800)
- PHP 8.0+
- A WritersProof API key (get one at https://writersproof.com)

### Installation

1. Copy the `cpoe_moodle` directory to `local/writersproof` in your Moodle installation
2. Visit **Site administration > Notifications** to trigger the install
3. Go to **Site administration > Plugins > Local plugins > WritersProof** to configure

### Configuration

All configuration is done through the Moodle admin UI at **Site administration > Plugins > Local plugins > WritersProof**:

| Setting | Description | Default |
|---------|-------------|---------|
| Enabled | Enable/disable the plugin | Disabled |
| API Key | WritersProof API key | (empty) |
| Witness Assignments | Monitor assignment submissions | Enabled |
| Witness Forums | Monitor forum posts | Enabled |
| Witness Wikis | Monitor wiki edits | Enabled |
| Checkpoint Interval | Seconds between content checkpoints | 60 |

### No .env File Needed

This is a standard Moodle local plugin. Configuration is stored in the Moodle database via the Settings API (`set_config` / `get_config`). No `.env` file is required.

## Features

- **Assignment monitoring**: Captures evidence during assignment text submissions
- **Forum monitoring**: Captures evidence for forum posts and replies
- **Wiki monitoring**: Captures evidence during collaborative wiki editing
- **Per-activity control**: Enable/disable witnessing per content type
- **Instructor dashboard**: View authorship evidence for student submissions

## Architecture

```
Moodle Events --> Event Observer --> WritersProof API
                        |
              Content Hasher (SHA-256)
              WritersProof Client (session/event/checkpoint)
```

The plugin hooks into Moodle's event system to detect content creation and modification. It uses Moodle's `\core\event` API to observe submission events without modifying core code.

## Security

- Content is never stored externally -- only SHA-256 hashes are transmitted
- API key is stored in Moodle's config database (encrypted at rest if Moodle is configured for it)
- All external API calls use TLS
- Plugin respects Moodle's capability system for access control
- Input is sanitized via Moodle's built-in cleaning functions

## Plugin Details

- **Component**: `local_writersproof`
- **Version**: 1.0.0 (2026052900)
- **Minimum Moodle**: 4.1
- **Maturity**: Stable

## License

GPL-3.0-or-later -- Copyright 2024-2026 Writers Logic LLC
