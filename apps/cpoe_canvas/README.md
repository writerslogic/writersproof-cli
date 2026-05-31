# WritersProof for Canvas LMS

Cryptographic authorship attestation integration for Instructure Canvas. Uses LTI 1.3 to embed authorship verification into assignments and captures content change events via webhooks.

## How It Works

1. Students launch WritersProof from within Canvas via LTI 1.3
2. Canvas sends webhooks when submissions are created/updated
3. Content hashes are captured (never raw content)
4. Evidence events are shipped to WritersProof for cryptographic witnessing
5. Instructors can verify authorship evidence for student submissions

## Setup

### Prerequisites

- Node.js 18+
- A Canvas LMS instance with LTI 1.3 and API access
- A WritersProof API key (get one at https://writersproof.com)

### Installation

```bash
cd apps/cpoe_canvas
npm install
cp .env.example .env
# Edit .env with your credentials
npm start
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `CANVAS_PLATFORM_URL` | Canvas instance URL (e.g. `https://school.instructure.com`) | Yes |
| `CANVAS_CLIENT_ID` | Canvas Developer Key client ID (from LTI key) | Yes |
| `SESSION_SECRET` | Express session secret (random string) | Yes |
| `WRITERSPROOF_API_KEY` | WritersProof API key | Yes |
| `CANVAS_ACCESS_TOKEN` | Canvas API access token (for content monitoring) | No |
| `CANVAS_WEBHOOK_SECRET` | Webhook signing secret | No |
| `TOOL_HOST_URL` | Public URL of this server (default: `http://localhost:PORT`) | No |
| `PORT` | Server listen port (default: `3004`) | No |
| `NODE_ENV` | Set to `production` for secure cookies | No |

### Canvas LTI 1.3 Setup

1. In Canvas Admin, go to **Developer Keys > + Developer Key > LTI Key**
2. Use the configuration from `GET /lti/config`:
   - **OIDC Login URL**: `https://your-server.example.com/lti/login`
   - **Launch URL**: `https://your-server.example.com/lti/launch`
   - **JWKS URL**: `https://your-server.example.com/.well-known/jwks.json`
3. Enable the Developer Key and copy the **Client ID**
4. Add the tool to courses via **Settings > Apps > + App**

### Webhook Configuration

1. Use the Canvas API or admin UI to subscribe to events:
   - **URL**: `https://your-server.example.com/webhooks/canvas`
   - **Events**: `submission_created`, `submission_updated`

## API Endpoints

- `POST /webhooks/canvas` -- Receives Canvas webhooks
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
Canvas --> LTI 1.3 Launch --> Express Server --> WritersProof API
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
