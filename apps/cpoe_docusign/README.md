# WritersProof for DocuSign

Cryptographic authorship attestation integration for DocuSign. Captures envelope events (sent, delivered, completed) and ships tamper-evident evidence to the WritersProof API.

## How It Works

1. DocuSign Connect sends webhook notifications when envelope status changes
2. This integration captures content hashes from envelope documents (never raw content)
3. Evidence events are shipped to WritersProof for cryptographic witnessing
4. Authors can export verifiable proof of their document signing process

## Setup

### Prerequisites

- Node.js 18+
- A DocuSign developer account with API access
- A WritersProof API key (get one at https://writersproof.com)

### Installation

```bash
cd apps/cpoe_docusign
npm install
cp .env.example .env
# Edit .env with your credentials
npm start
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DOCUSIGN_INTEGRATION_KEY` | DocuSign integration key (client ID) | Yes |
| `DOCUSIGN_USER_ID` | DocuSign user ID for JWT grant impersonation | Yes |
| `DOCUSIGN_ACCOUNT_ID` | DocuSign account ID | Yes |
| `DOCUSIGN_RSA_PRIVATE_KEY` | RSA private key (PEM string) for JWT authentication | Yes |
| `WRITERSPROOF_API_KEY` | WritersProof API key | Yes |
| `CONNECT_HMAC_KEY` | DocuSign Connect HMAC key for webhook verification | Yes |
| `DOCUSIGN_BASE_URL` | DocuSign API base URL (default: `https://demo.docusign.net/restapi`) | No |
| `DOCUSIGN_CLIENT_SECRET` | Client secret for authorization code flow | No |
| `CONNECT_HMAC_KEY_2` | Secondary HMAC key for key rotation | No |
| `APP_BASE_URL` | Public URL of this server (for OAuth redirect) | No |
| `PORT` | Server listen port (default: `3008`) | No |

### DocuSign Setup

1. Create an app in the [DocuSign Developer Center](https://developers.docusign.com/)
2. Generate an RSA key pair and copy the private key
3. Grant consent for JWT authentication
4. In **Connect**, create a custom configuration:
   - **URL**: `https://your-server.example.com/webhooks/docusign`
   - **Events**: Envelope Sent, Delivered, Completed
   - Enable **HMAC** and copy the key

### Authentication

The integration supports two authentication modes:
- **JWT Grant** (recommended for server-to-server): Uses RSA private key
- **Authorization Code**: Visit `/oauth/authorize` for interactive flow

## API Endpoints

- `POST /webhooks/docusign` -- Receives DocuSign Connect notifications (HMAC-verified)
- `GET /api/evidence/:envelopeId` -- Retrieve evidence for an envelope
- `GET /api/status` -- Service status and active session count
- `GET /oauth/authorize` -- Initiates OAuth flow
- `GET /oauth/callback` -- OAuth callback
- `GET /health` -- Health check

## Architecture

```
DocuSign Connect --> Webhook --> Express Server --> WritersProof API
                                      |
                            ContentMonitor (SHA-256 hashing, JWT auth)
                            WritersProofClient (session/event/checkpoint)
```

## Security

- All incoming webhooks are verified via DocuSign Connect HMAC-SHA256 signature
- Supports HMAC key rotation with primary and secondary keys
- Content is never stored -- only SHA-256 hashes are transmitted
- JWT tokens are cached and refreshed automatically
- API keys are stored in environment variables, never committed
- All API calls use TLS with 30s timeout and 3-retry with backoff

## License

AGPL-3.0-only -- Copyright 2024-2026 Writers Logic LLC
