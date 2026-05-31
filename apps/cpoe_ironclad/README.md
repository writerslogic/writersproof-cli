# WritersProof for Ironclad

Cryptographic authorship attestation integration for Ironclad CLM. Captures workflow events from contract lifecycle management and ships tamper-evident evidence to the WritersProof API.

## How It Works

1. Ironclad sends webhooks when workflow events occur (contract creation, edits, approvals)
2. This integration captures content hashes (never raw content)
3. Evidence events are shipped to WritersProof for cryptographic witnessing
4. Authors can export verifiable proof of their contract drafting process

## Setup

### Prerequisites

- Node.js 18+
- An Ironclad account with API access
- A WritersProof API key (get one at https://writersproof.com)

### Installation

```bash
cd apps/cpoe_ironclad
npm install
cp .env.example .env
# Edit .env with your credentials
npm start
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `IRONCLAD_API_KEY` | Ironclad API key (if using API key auth) | One of API key or OAuth |
| `IRONCLAD_CLIENT_ID` | Ironclad OAuth client ID | One of API key or OAuth |
| `IRONCLAD_CLIENT_SECRET` | Ironclad OAuth client secret | One of API key or OAuth |
| `IRONCLAD_WEBHOOK_SECRET` | Ironclad webhook signing secret | Yes |
| `WRITERSPROOF_API_KEY` | WritersProof API key | Yes |
| `APP_BASE_URL` | Public URL of this server (for OAuth redirect) | No |
| `PORT` | Server listen port (default: `3009`) | No |

### Authentication

The integration supports two authentication modes:
- **API Key**: Set `IRONCLAD_API_KEY` for simple authentication
- **OAuth**: Set `IRONCLAD_CLIENT_ID` and `IRONCLAD_CLIENT_SECRET`, then visit `/oauth/authorize`

### Ironclad Setup

1. In Ironclad, go to **Company Settings > API** and create credentials
2. Configure a webhook:
   - **URL**: `https://your-server.example.com/webhooks/ironclad`
   - **Events**: Workflow created, updated, signed, completed
   - Copy the signing secret

## API Endpoints

- `POST /webhooks/ironclad` -- Receives Ironclad webhooks (signature-verified)
- `GET /api/evidence/:workflowId` -- Retrieve evidence for a workflow
- `GET /api/status` -- Service status, auth mode, and active sessions
- `GET /oauth/authorize` -- Initiates OAuth flow
- `GET /oauth/callback` -- OAuth callback
- `GET /health` -- Health check

## Architecture

```
Ironclad --> Webhook --> Express Server --> WritersProof API
                               |
                     ContentMonitor (SHA-256 hashing)
                     WritersProofClient (session/event/checkpoint)
```

## Security

- All incoming webhooks are verified via HMAC-SHA256 signature
- Content is never stored -- only SHA-256 hashes are transmitted
- API keys are stored in environment variables, never committed
- OAuth tokens are refreshed automatically
- All API calls use TLS with 30s timeout and 3-retry with backoff

## License

AGPL-3.0-only -- Copyright 2024-2026 Writers Logic LLC
