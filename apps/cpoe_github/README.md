# WritersProof for GitHub

Cryptographic authorship attestation integration for GitHub. Captures content change events from issues, pull requests, discussions, and wiki edits, then ships tamper-evident evidence to the WritersProof API.

## How It Works

1. GitHub sends webhooks when issues, PRs, discussions, or wiki pages are created/updated
2. This integration captures content hashes (never raw content)
3. Evidence events are shipped to WritersProof for cryptographic witnessing
4. Authors can export verifiable proof of their writing process

## Setup

### Prerequisites

- Node.js 18+
- A GitHub App with appropriate permissions
- A WritersProof API key (get one at https://writersproof.com)

### Installation

```bash
cd apps/cpoe_github
npm install
cp .env.example .env
# Edit .env with your credentials
npm start
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GITHUB_APP_ID` | GitHub App ID | Yes |
| `GITHUB_PRIVATE_KEY_PATH` | Path to GitHub App private key PEM file | Yes |
| `GITHUB_WEBHOOK_SECRET` | GitHub webhook secret for HMAC-SHA256 verification | Yes |
| `WRITERSPROOF_API_KEY` | WritersProof API key | Yes |
| `PORT` | Server listen port (default: `3002`) | No |

### GitHub App Setup

1. Go to **Settings > Developer settings > GitHub Apps > New GitHub App**
2. Set the webhook URL to `https://your-server.example.com/webhooks/github`
3. Generate and set a **Webhook secret**
4. Grant permissions: Issues (Read), Pull requests (Read), Discussions (Read)
5. Subscribe to events: Issues, Issue comments, Pull requests, PR reviews, PR review comments, Discussions, Discussion comments, Wiki (Gollum)
6. Generate a private key and save the PEM file
7. Install the app on your repositories

### Webhook Registration API

You can also register webhooks programmatically:

```bash
curl -X POST https://your-server.example.com/api/setup \
  -H "Content-Type: application/json" \
  -d '{"installationId": "123", "owner": "org", "repo": "repo", "webhookUrl": "https://your-server.example.com/webhooks/github"}'
```

## API Endpoints

- `POST /webhooks/github` -- Receives GitHub webhooks (HMAC-SHA256 verified)
- `POST /api/setup` -- Register webhook on a repository
- `GET /health` -- Health check

## Architecture

```
GitHub --> Webhook --> Express Server --> WritersProof API
                             |
                   ContentMonitor (SHA-256 hashing, installation tokens)
                   WritersProofClient (session/event/checkpoint)
```

## Security

- All incoming webhooks are verified via HMAC-SHA256 signature
- Content is never stored -- only SHA-256 hashes are transmitted
- API keys are stored in environment variables, never committed
- GitHub App authentication uses RSA private key (JWT)
- All API calls use TLS with 30s timeout and 3-retry with backoff

## License

AGPL-3.0-only -- Copyright 2024-2026 Writers Logic LLC
