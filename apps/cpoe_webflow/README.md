# WritersProof for Webflow

Cryptographic authorship attestation integration for Webflow. Captures CMS content change events and ships tamper-evident evidence to the WritersProof API.

## How It Works

1. Webflow sends webhooks when CMS items are created or updated
2. This integration captures content hashes (never raw content)
3. Evidence events are shipped to WritersProof for cryptographic witnessing
4. Authors can export verifiable proof of their writing process

## Setup

### Prerequisites

- Node.js 18+
- A Webflow site with CMS access
- A WritersProof API key (get one at https://writersproof.com)

### Installation

```bash
cd apps/cpoe_webflow
npm install
cp .env.example .env
# Edit .env with your credentials
npm start
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `WEBFLOW_CLIENT_ID` | Webflow OAuth application client ID | Yes |
| `WEBFLOW_CLIENT_SECRET` | Webflow OAuth application client secret | Yes |
| `WRITERSPROOF_API_KEY` | WritersProof API key | Yes |
| `WEBHOOK_SECRET` | Webflow webhook signing secret | Yes |
| `WEBFLOW_ACCESS_TOKEN` | Pre-existing access token (skips OAuth flow) | No |
| `PORT` | Server listen port (default: `3001`) | No |

### Webflow Setup

1. Create an app at [Webflow Dashboard](https://webflow.com/dashboard/workspace/integrations)
2. Set the redirect URI to `https://your-server.example.com/oauth/callback`
3. Required scopes: `cms:read`, `cms:write`, `sites:read`, `webhooks:write`
4. Copy the **Client ID** and **Client Secret**

### OAuth Flow

1. Visit `https://your-server.example.com/oauth/authorize` to start the OAuth flow
2. Authorize the app in Webflow
3. The integration will automatically begin processing webhooks

### Webhook Configuration

After OAuth, register webhooks via the Webflow API or dashboard:
- **URL**: `https://your-server.example.com/webhooks/webflow`
- **Events**: `collection_item_created`, `collection_item_changed`

## API Endpoints

- `POST /webhooks/webflow` -- Receives Webflow webhooks (HMAC-SHA256 verified)
- `GET /oauth/authorize` -- Initiates OAuth flow
- `GET /oauth/callback` -- OAuth callback
- `GET /health` -- Health check

## Architecture

```
Webflow --> Webhook --> Express Server --> WritersProof API
                              |
                    ContentMonitor (SHA-256 hashing, OAuth token)
                    WritersProofClient (session/event/checkpoint)
```

## Security

- All incoming webhooks are verified via HMAC-SHA256 signature (`X-Webflow-Signature`)
- Content is never stored -- only SHA-256 hashes are transmitted
- API keys are stored in environment variables, never committed
- All API calls use TLS with 30s timeout and 3-retry with backoff

## License

AGPL-3.0-only -- Copyright 2024-2026 Writers Logic LLC
