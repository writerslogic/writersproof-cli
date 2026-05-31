# WritersProof for Notion

Cryptographic authorship attestation integration for Notion. Polls for page changes and ships tamper-evident evidence to the WritersProof API.

## How It Works

1. The integration polls Notion's API for recently edited pages (Notion does not support webhooks)
2. Content hashes are captured (never raw content)
3. Evidence events are shipped to WritersProof for cryptographic witnessing
4. Authors can export verifiable proof of their writing process

## Setup

### Prerequisites

- Node.js 18+
- A Notion workspace with API access
- A WritersProof API key (get one at https://writersproof.com)

### Installation

```bash
cd apps/cpoe_notion
npm install
cp .env.example .env
# Edit .env with your credentials
npm start
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `NOTION_API_KEY` | Notion internal integration token (for single-workspace use) | One of API key or OAuth |
| `NOTION_CLIENT_ID` | Notion OAuth application client ID (for multi-workspace) | One of API key or OAuth |
| `NOTION_CLIENT_SECRET` | Notion OAuth application client secret | With `NOTION_CLIENT_ID` |
| `WRITERSPROOF_API_KEY` | WritersProof API key | Yes |
| `POLL_INTERVAL_MS` | Polling interval in milliseconds (default: `60000`) | No |
| `OAUTH_REDIRECT_URI` | OAuth callback URL | No |
| `PORT` | Server listen port (default: `3006`) | No |

### Authentication

The integration supports two authentication modes:
- **Internal integration**: Set `NOTION_API_KEY` for single-workspace use
- **Public OAuth**: Set `NOTION_CLIENT_ID` and `NOTION_CLIENT_SECRET`, then visit `/oauth/authorize`

### Notion Setup

1. Go to [Notion Integrations](https://www.notion.so/my-integrations) and create a new integration
2. For internal use, copy the **Internal Integration Token**
3. For public OAuth, configure redirect URI and copy client credentials
4. Share the pages/databases you want to monitor with the integration

### Starting the Poller

After authentication, start polling via the API:

```bash
curl -X POST https://your-server.example.com/api/start-polling
```

## API Endpoints

- `GET /oauth/authorize` -- Initiates OAuth flow (public integration mode)
- `GET /oauth/callback` -- OAuth callback
- `POST /api/start-polling` -- Start polling Notion for changes
- `POST /api/stop-polling` -- Stop polling
- `GET /api/status` -- Polling status
- `GET /api/evidence/:pageId` -- Retrieve evidence for a page
- `POST /api/finalize/:pageId` -- Finalize evidence session for a page
- `GET /health` -- Health check

## Architecture

```
Notion API <-- Poll --> Express Server --> WritersProof API
                              |
                    ContentMonitor (SHA-256 hashing, page search)
                    WritersProofClient (session/event/checkpoint)
```

## Security

- Content is never stored -- only SHA-256 hashes are transmitted
- API keys are stored in environment variables, never committed
- OAuth tokens are stored per-workspace
- All API calls use TLS with 30s timeout and 3-retry with backoff

## License

AGPL-3.0-only -- Copyright 2024-2026 Writers Logic LLC
