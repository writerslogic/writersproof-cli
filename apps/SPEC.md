# WritersProof Platform Integrations — Build Spec

## Overview

Build foundational integration codebase for 12 platforms. Each integration acts as a client-side or server-side telemetry bridge that hooks into the platform's content editing interface and ships authorship evidence to the WritersProof API.

## Target Platforms (empty, to be built)

| Platform | Type | Integration Model |
|----------|------|-------------------|
| WordPress | CMS | PHP plugin + Gutenberg JS hooks |
| Moodle | LMS | PHP plugin (local_writersproof) |
| Ghost | CMS | Node.js + Admin API + webhooks |
| Webflow | Website builder | Node.js + Data API + webhooks |
| GitHub | Dev platform | GitHub App + webhooks |
| Linear | Project mgmt | OAuth app + GraphQL + webhooks |
| Canvas | LMS | Node.js + LTI 1.3 + Canvas API |
| Blackboard | LMS | Node.js + LTI 1.3 + REST API |
| Notion | Productivity | Node.js + API polling |
| Clio | Legal | Node.js + OAuth + REST API |
| DocuSign | eSignature | Node.js + Connect webhooks |
| Ironclad | CLM | Node.js + webhooks + REST API |

## Existing Reference Implementations

All existing integrations use the same WritersProof API contract:
- Base URL: `https://api.writerslogic.com/v1`
- Auth: `Authorization: Bearer {apiKey}`
- Headers: `X-Client-Platform: {platform}`, `X-Client-Version: 1.0.0`
- Endpoints: POST /sessions, POST /sessions/{id}/events, POST /sessions/{id}/checkpoints, POST /sessions/{id}/finalize, GET /sessions/{id}/evidence, POST /verify
- Optional: POST /anchor, POST /beacon, POST /stego/sign, POST /declaration
- All implement 3-retry with 429/5xx handling, 30s timeout

## Standard Node.js Integration Structure

```
cpoe_{platform}/
├── package.json
├── tsconfig.json
├── LICENSE
├── src/
│   ├── app.ts                    — Express server, OAuth, webhook receiver
│   ├── services/
│   │   ├── WritersProofClient.ts — HTTP client to WritersProof API
│   │   └── ContentMonitor.ts     — Platform-specific content fetching + hashing
│   └── webhooks/
│       └── events.ts             — Platform webhook handlers
└── store/                        — Store listing metadata
```

## Standard PHP Plugin Structure (WordPress/Moodle)

WordPress:
```
cpoe_wordpress/
├── writersproof.php              — Plugin entry point
├── includes/
│   ├── class-writersproof-client.php
│   ├── class-writersproof-monitor.php
│   ├── class-writersproof-admin.php
│   └── class-writersproof-rest.php
├── assets/js/
│   └── editor-hooks.js           — Gutenberg + Classic editor hooks
├── assets/css/
│   └── admin.css
├── readme.txt                    — WP plugin readme
└── store/
```

## Content Monitoring Pattern

All integrations must:
1. Capture content snapshots via platform API
2. SHA-256 hash the content body (never store raw content)
3. Diff against previous snapshot: charDelta, wordDelta, paragraphDelta
4. Generate typed events: content_change, structure_change, field_modified
5. Submit events to WritersProof API in batches

## Session Lifecycle

1. **Start**: Auto-start on content creation, or manual trigger
2. **Events**: Continuous monitoring via polling or webhooks
3. **Checkpoints**: Periodic snapshots with content hash
4. **Finalize**: On publish/save/close, finalize session with final snapshot

## Security Requirements

- Webhook signature verification (HMAC-SHA256) for all incoming webhooks
- API keys stored in platform-native secure storage
- No raw content logged or transmitted
- OAuth tokens refreshed automatically
- Rate limiting on event submission
