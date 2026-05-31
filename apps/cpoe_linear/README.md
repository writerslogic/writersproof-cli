# WritersProof for Linear

Cryptographic authorship attestation integration for Linear. Captures content change events from issues and comments, then ships tamper-evident evidence to the WritersProof API.

## How It Works

1. Linear sends webhooks when issues or comments are created/updated
2. This integration captures content hashes (never raw content)
3. Evidence events are shipped to WritersProof for cryptographic witnessing
4. Authors can export verifiable proof of their writing process

## Setup

### Prerequisites

- Node.js 18+
- A Linear workspace with API access
- A WritersProof API key (get one at https://writersproof.com)

### Installation

```bash
cd apps/cpoe_linear
npm install
cp .env.example .env
# Edit .env with your credentials
npm start
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `LINEAR_CLIENT_ID` | Linear OAuth application client ID | Yes |
| `LINEAR_CLIENT_SECRET` | Linear OAuth application client secret | Yes |
| `LINEAR_WEBHOOK_SECRET` | Linear webhook signing secret | Yes |
| `WRITERSPROOF_API_KEY` | WritersProof API key | Yes |
| `APP_BASE_URL` | Public URL of this server (for OAuth redirect) | No |
| `PORT` | Server listen port (default: `3003`) | No |

### Linear Setup

1. Go to **Settings > API > OAuth Applications** and create a new application
2. Set the redirect URI to `https://your-server.example.com/oauth/callback`
3. Copy the **Client ID** and **Client Secret**
4. Under **Settings > API > Webhooks**, create a webhook:
   - **URL**: `https://your-server.example.com/webhooks/linear`
   - Copy the signing secret

### OAuth Flow

1. Visit `https://your-server.example.com/oauth/authorize` to start the OAuth flow
2. Authorize the app in Linear
3. The integration will store the access token per organization

## API Endpoints

- `POST /webhooks/linear` -- Receives Linear webhooks (signature-verified)
- `GET /oauth/authorize` -- Initiates OAuth flow
- `GET /oauth/callback` -- OAuth callback
- `GET /health` -- Health check

## Architecture

```
Linear --> Webhook --> Express Server --> WritersProof API
                             |
                   ContentMonitor (SHA-256 hashing)
                   WritersProofClient (session/event/checkpoint)
```

## Security

- All incoming webhooks are verified via HMAC-SHA256 signature
- Content is never stored -- only SHA-256 hashes are transmitted
- API keys are stored in environment variables, never committed
- OAuth tokens are stored per-organization
- All API calls use TLS with 30s timeout and 3-retry with backoff

## License

AGPL-3.0-only -- Copyright 2024-2026 Writers Logic LLC
