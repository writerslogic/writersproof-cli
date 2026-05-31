# WritersProof for Clio

Cryptographic authorship attestation integration for Clio legal practice management. Captures content change events from documents, notes, and communications, then ships tamper-evident evidence to the WritersProof API.

## How It Works

1. Clio sends webhooks when documents, notes, or communications are created/updated
2. This integration captures content hashes (never raw content)
3. Evidence events are shipped to WritersProof for cryptographic witnessing
4. Authors can export verifiable proof of their writing process

## Setup

### Prerequisites

- Node.js 18+
- A Clio account with developer API access
- A WritersProof API key (get one at https://writersproof.com)

### Installation

```bash
cd apps/cpoe_clio
npm install
cp .env.example .env
# Edit .env with your credentials
npm start
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `CLIO_CLIENT_ID` | Clio OAuth application client ID | Yes |
| `CLIO_CLIENT_SECRET` | Clio OAuth application client secret | Yes |
| `CLIO_WEBHOOK_SECRET` | Clio webhook signing secret | Yes |
| `WRITERSPROOF_API_KEY` | WritersProof API key | Yes |
| `OAUTH_REDIRECT_URI` | OAuth callback URL (default: `http://localhost:PORT/oauth/callback`) | No |
| `PORT` | Server listen port (default: `3007`) | No |

### Clio Setup

1. Register a new application at [Clio Developer Portal](https://app.clio.com/nc/#/settings/developer_applications)
2. Set the redirect URI to `https://your-server.example.com/oauth/callback`
3. Copy the **Client ID** and **Client Secret**
4. Configure a webhook subscription pointing to `https://your-server.example.com/webhooks/clio`

### OAuth Flow

1. Visit `https://your-server.example.com/oauth/authorize` to start the OAuth flow
2. Authorize the app in Clio
3. The integration will automatically begin processing webhooks

## API Endpoints

- `POST /webhooks/clio` -- Receives Clio webhooks (signature-verified, requires OAuth)
- `GET /oauth/authorize` -- Initiates OAuth flow
- `GET /oauth/callback` -- OAuth callback
- `GET /api/evidence/:matterId` -- Retrieve evidence for a matter
- `GET /api/status` -- Authentication status
- `GET /health` -- Health check

## Architecture

```
Clio --> Webhook --> Express Server --> WritersProof API
                           |
                 ContentMonitor (SHA-256 hashing, OAuth tokens)
                 WritersProofClient (session/event/checkpoint)
```

## Security

- All incoming webhooks are verified via HMAC-SHA256 signature
- Content is never stored -- only SHA-256 hashes are transmitted
- API keys are stored in environment variables, never committed
- OAuth tokens are managed in-memory (use persistent storage in production)
- All API calls use TLS with 30s timeout and 3-retry with backoff

## License

AGPL-3.0-only -- Copyright 2024-2026 Writers Logic LLC
