# WritersProof for Ghost

Cryptographic authorship attestation integration for Ghost CMS. Captures content change events and ships tamper-evident evidence to the WritersProof API.

## How It Works

1. Ghost sends webhooks when posts are created or updated
2. This integration captures content hashes (never raw content)
3. Evidence events are shipped to WritersProof for cryptographic witnessing
4. Authors can export verifiable proof of their writing process

## Setup

### Prerequisites

- Node.js 18+
- A Ghost site with admin API access
- A WritersProof API key (get one at https://writersproof.com)

### Installation

```bash
cd apps/cpoe_ghost
npm install
cp .env.example .env
# Edit .env with your credentials
npm start
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GHOST_URL` | Your Ghost site URL (e.g. `https://myblog.ghost.io`) | Yes |
| `GHOST_ADMIN_API_KEY` | Ghost Admin API key (Content integrations in Ghost admin) | Yes |
| `WRITERSPROOF_API_KEY` | WritersProof API key | Yes |
| `WEBHOOK_SECRET` | Shared secret for webhook signature verification | Yes |
| `PORT` | Server listen port (default: `3000`) | No |

### Webhook Configuration

1. In Ghost Admin, go to **Settings > Integrations > Add custom integration**
2. Create a new integration and copy the **Admin API Key**
3. Under **Webhooks**, add a new webhook:
   - **Event**: Post published / Post updated
   - **Target URL**: `https://your-server.example.com/webhooks/ghost`
4. Set the webhook secret header (`X-Ghost-Webhook-Secret`) to match your `WEBHOOK_SECRET`

## API Endpoints

- `POST /webhooks/ghost` -- Receives Ghost webhooks (secret-verified)
- `GET /health` -- Health check

## Architecture

```
Ghost CMS --> Webhook --> Express Server --> WritersProof API
                                |
                      ContentMonitor (SHA-256 hashing)
                      WritersProofClient (session/event/checkpoint)
```

## Security

- All incoming webhooks are verified via constant-time comparison of the shared secret
- Content is never stored -- only SHA-256 hashes are transmitted
- API keys are stored in environment variables, never committed
- All API calls use TLS with 30s timeout and 3-retry with backoff

## License

AGPL-3.0-only -- Copyright 2024-2026 Writers Logic LLC
