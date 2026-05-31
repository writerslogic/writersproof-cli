# WritersProof for Blackboard Learn

Cryptographic authorship attestation integration for Blackboard Learn LMS. Uses LTI 1.3 to embed authorship verification into assignments and captures content change events via webhooks.

## How It Works

1. Students launch WritersProof from within Blackboard via LTI 1.3
2. Blackboard sends webhooks when submissions are created/updated
3. Content hashes are captured (never raw content)
4. Evidence events are shipped to WritersProof for cryptographic witnessing
5. Instructors can verify authorship evidence for student submissions

## Setup

### Prerequisites

- Node.js 18+
- A Blackboard Learn instance with REST API and LTI 1.3 support
- A WritersProof API key (get one at https://writersproof.com)

### Installation

```bash
cd apps/cpoe_blackboard
npm install
cp .env.example .env
# Edit .env with your credentials
npm start
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `BLACKBOARD_PLATFORM_URL` | Blackboard Learn instance URL (e.g. `https://school.blackboard.com`) | Yes |
| `BLACKBOARD_CLIENT_ID` | Blackboard REST API / LTI client ID | Yes |
| `BLACKBOARD_CLIENT_SECRET` | Blackboard REST API client secret | Yes |
| `SESSION_SECRET` | Express session secret (random string) | Yes |
| `WRITERSPROOF_API_KEY` | WritersProof API key | Yes |
| `BLACKBOARD_WEBHOOK_SECRET` | Webhook signing secret | No |
| `TOOL_HOST_URL` | Public URL of this server (default: `http://localhost:PORT`) | No |
| `PORT` | Server listen port (default: `3005`) | No |
| `NODE_ENV` | Set to `production` for secure cookies | No |

### Blackboard LTI 1.3 Setup

1. In Blackboard Admin, go to **System Admin > LTI Tool Providers > Register LTI 1.3 Tool**
2. Use the configuration from `GET /lti/config`:
   - **OIDC Login URL**: `https://your-server.example.com/lti/login`
   - **Launch URL**: `https://your-server.example.com/lti/launch`
   - **JWKS URL**: `https://your-server.example.com/.well-known/jwks.json`
3. Copy the **Client ID** provided by Blackboard

### Webhook Configuration

1. Register a webhook in Blackboard's REST API:
   - **URL**: `https://your-server.example.com/webhooks/blackboard`
   - **Events**: Content created, updated

## API Endpoints

- `POST /webhooks/blackboard` -- Receives Blackboard webhooks
- `GET /lti/login` -- LTI 1.3 OIDC login initiation
- `POST /lti/launch` -- LTI 1.3 resource launch
- `GET /lti/config` -- LTI tool configuration descriptor
- `GET /.well-known/jwks.json` -- JWKS endpoint for LTI verification
- `GET /api/session/status` -- Check active LTI session
- `GET /api/evidence/:sessionId` -- Retrieve evidence (requires LTI session)
- `POST /api/verify` -- Verify evidence (requires LTI session)
- `GET /health` -- Health check

## Architecture

```
Blackboard --> LTI 1.3 Launch --> Express Server --> WritersProof API
           --> Webhook --------->       |
                                ContentMonitor (SHA-256 hashing)
                                WritersProofClient (session/event/checkpoint)
```

## Security

- LTI 1.3 launches are verified via OIDC and JWT signature validation
- Webhook payloads are verified via HMAC-SHA256 when configured
- Content is never stored -- only SHA-256 hashes are transmitted
- Sessions use secure, httpOnly cookies with SameSite=None for LTI iframe embedding
- API keys are stored in environment variables, never committed
- All API calls use TLS with 30s timeout and 3-retry with backoff

## License

AGPL-3.0-only -- Copyright 2024-2026 Writers Logic LLC
