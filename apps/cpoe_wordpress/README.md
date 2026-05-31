# WritersProof for WordPress

Cryptographic authorship attestation plugin for WordPress. Automatically captures writing process evidence as authors create and edit posts, then ships tamper-evident proof to the WritersProof API.

## How It Works

1. When an author edits a post in the Block Editor (Gutenberg), the plugin captures content checkpoints
2. Content hashes are computed (never raw content sent externally)
3. Evidence events are shipped to WritersProof for cryptographic witnessing
4. When a post is published, the session is finalized and an evidence score is stored
5. Authors can export verifiable proof of their writing process

## Setup

### Prerequisites

- WordPress 6.0+
- PHP 8.0+
- A WritersProof API key (get one at https://writersproof.com)

### Installation

1. Copy the `cpoe_wordpress` directory to `wp-content/plugins/writersproof`
2. Activate the plugin in **Plugins > Installed Plugins**
3. Go to **Settings > WritersProof** and enter your API key

### Configuration

All configuration is done through the WordPress admin UI at **Settings > WritersProof**:

| Setting | Description | Default |
|---------|-------------|---------|
| API Key | WritersProof API key | (empty) |
| Auto Start | Automatically start witnessing when editing | Enabled |
| Checkpoint Interval | Seconds between content checkpoints | 60 |
| Post Types | Which post types to monitor | Posts, Pages |

### No .env File Needed

This is a standard WordPress plugin. Configuration is stored in the WordPress database via the Settings API. No `.env` file is required.

## Features

- **Block Editor integration**: Sidebar panel shows witnessing status and evidence score
- **Automatic checkpoints**: Content hashes captured at configurable intervals
- **Publish finalization**: Evidence session automatically finalized on publish
- **Evidence score**: Stored as post meta and visible in the editor
- **REST API**: Full REST API for session management

## REST API Endpoints

All endpoints require WordPress authentication (nonce-based):

- `POST /wp-json/writersproof/v1/session/start` -- Start a witnessing session
- `POST /wp-json/writersproof/v1/session/checkpoint` -- Create a checkpoint
- `POST /wp-json/writersproof/v1/session/finalize` -- Finalize a session
- `GET /wp-json/writersproof/v1/session/status` -- Get session status
- `GET /wp-json/writersproof/v1/evidence/:sessionId` -- Retrieve evidence

## Architecture

```
Block Editor --> REST API --> WritersProof_Rest --> WritersProof API
                                    |
                          WritersProof_Monitor (SHA-256 hashing)
                          WritersProof_Client (session/event/checkpoint)
```

### Database

The plugin creates a `wp_writersproof_sessions` table on activation to track evidence sessions per post.

### Post Meta Fields

| Meta Key | Description |
|----------|-------------|
| `_writersproof_session_id` | Active evidence session ID |
| `_writersproof_evidence_score` | Evidence quality score (0-100) |
| `_writersproof_status` | Witnessing status |
| `_writersproof_last_snapshot` | Last captured content state (internal) |

## Security

- All REST endpoints require WordPress authentication
- Content is never stored externally -- only SHA-256 hashes are transmitted
- API key is stored in the WordPress database (via `update_option`)
- All external API calls use TLS
- Input is sanitized via WordPress sanitization functions

## License

GPL-2.0-or-later -- Copyright 2024-2026 Writers Logic LLC
