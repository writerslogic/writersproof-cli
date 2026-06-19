# Full Notarization (Paid Tier) — Implementation Spec

Status: **server side DONE (2026-06-19), client side pending a macOS release.** The worker `/v1/publish` is now tier-aware: free → lightweight registration; paid (`wp_subscriptions.status=active`) + `evidence_b64` supplied → verifies `sha256(packet)==evidence_hash`, CA-counter-signs (`NOTARIZE_CA_PRIVATE_KEY`), stores in R2 (`EVIDENCE_STORE`), records `r2_key`/sizes/`ca_signature`/`tier`. Provenance surfaces `stored`/`countersigned`. Deployed live. No paid users exist yet (`wp_subscriptions` = 0 rows).

**Engine DONE (2026-06-19):** `ffi_publish_evidence` now self-serves the packet — it calls `build_wire_packet_with_ai(path, "standard", ...)`, base64-encodes the CBOR, and sets `PublishRequest.evidence_b64` when ≤700 KB (else lightweight). NO FFI signature change, so NO uniffi binding regen. Also fixed a systemic bug: the worker read snake_case but the serde clients send camelCase — `/v1/publish` request+response are now camelCase (commit writersproof `1530e033`). NOTE: `anchor` and `text-attestation` worker routes have the SAME camelCase bug (request AND response) — that's why `wp_transparency_log`/`wp_text_attestations` are empty; fix them the same way (out of scope here).

**Remaining — macOS UI only (Xcode build required, unverifiable in this env):** `ffi_publish_evidence` is still not called by any macOS view. To activate, mirror the existing `anchorToWritersProof` wiring:
1. `EngineService/EngineServiceProtocol.swift` — add `func publishEvidence(documentPath:attestation:aiDeclaration:) async -> FfiPublishResult` (update ALL conformers + any mock/preview).
2. `EngineService/EngineService.swift` — implement it via `ffiWithTimeout("publishEvidence", { ffiPublishEvidence(documentPath:attestation:aiDeclaration:) })` (pattern at line ~781).
3. `Service/CPoEService+Actions.swift` — add a `publishEvidence` action wrapper (pattern at ~760).
4. `Popover/ExportFormView.swift` — add a "Publish to WritersProof" action/option that collects an author attestation string (required, non-empty) + optional AI declaration, calls the action, and shows the returned `canonicalUrl` (`verify.writersproof.com/v/<hash>`). The anchor toggle at line ~233 is the closest pattern.
Server + engine are ready: the moment macOS calls `ffiPublishEvidence`, evidence appears on the verify page (free → lightweight; paid → R2-stored + CA-countersigned).

## Goal

Today every publish is **lightweight**: `/v1/publish` records the evidence hash + provenance metadata in `wp_notarizations` and returns `verify.writersproof.com/v/<hash>`. The packet is not stored or counter-signed.

**Full notarization** (paid) additionally: stores the actual `.cpop` evidence packet in R2, CA-counter-signs it, and records sizes + expiry. The schema and bindings already support it:
- `wp_notarizations.r2_key`, `countersigned_size`, `original_size`, `tier`, `expires_at`, `expired` (cron already sweeps expired R2 objects in `apps/api/src/cron.ts`).
- Worker bindings present: `EVIDENCE_STORE` (R2 bucket `writersproof-evidence`), `NOTARIZE_CA_PRIVATE_KEY`, `NOTARIZE_CA_PUBLIC_KEY`.

## The blocker

The desktop `PublishRequest` sends only `{ evidence_hash, author_did, signature, attestation, checkpoint_count, document_name?, ai_declaration? }` — **not the packet bytes**. Full notarization cannot store/counter-sign what it never receives. So this requires a client change + a new app release; it cannot be a server-only hotfix.

## Work items

### 1. Client (writerslogic — Rust engine + FFI)
- `crates/cpoe/src/writersproof/types.rs`: add `evidence_b64: Option<String>` (base64 of the `.cpop`) to `PublishRequest`, or switch publish to a multipart/octet-stream upload (preferred if packets can exceed ~700 KB after base64, since `/v1/*` has a 1 MB body limit — bump `bodyLimit` for `/v1/publish` accordingly).
- `crates/cpoe/src/ffi/writersproof_ffi.rs` (`ffi_publish_evidence`) / `evidence_export.rs`: read the packet bytes from the exported `.cpop` and include them.
- Keep hash+signature for the lightweight/free path (server decides tier).
- Rebuild FFI + macOS app (release required for users to benefit).

### 2. Worker (writersproof — `apps/api/src/routes/publish.ts`)
Branch on subscription tier (look up `wp_subscriptions` for the authed `userId`; default `free`):
- **free** → current lightweight behavior (unchanged).
- **paid** → require packet bytes; then:
  1. Verify `sha256(packet) === evidence_hash` (reject mismatch).
  2. CA-counter-sign: Ed25519 over the packet (or wrap in COSE_Sign1) with `NOTARIZE_CA_PRIVATE_KEY`; match whatever the verifier/`/v1/provenance` expects.
  3. `EVIDENCE_STORE.put(r2_key, countersignedBytes)` where `r2_key = \`${userId}/${evidence_hash}.cpop\``.
  4. Insert `wp_notarizations` with `r2_key`, `original_size`, `countersigned_size`, `tier`, `expires_at` (free: null/never; paid: per retention policy).
- Enforce a larger `bodyLimit` for `/v1/publish` if accepting packets.

### 3. Verify surface
- `apps/api/src/routes/provenance.ts`: add `r2_key`/`countersigned`/`tier` to the `wp_notarizations` select so the verify page can show a "stored & counter-signed" badge for paid records, and a download link.

## Acceptance
- Free user publish → lightweight row, `verify.writersproof.com/v/<hash>` resolves (already true).
- Paid user publish with packet → R2 object created, `wp_notarizations` row has non-null `r2_key`/sizes, counter-signature verifies against `NOTARIZE_CA_PUBLIC_KEY`, verify page shows the stored badge.
- vitest covers: hash/packet mismatch rejected; tier branch selects free vs paid; idempotent re-publish returns existing record.

## Related improvement (independent, smaller)
A user who publishes with `ai_declaration` today has it stored on `wp_notarizations.ai_declaration`, but `/v1/provenance/:hash` reads AI disclosure only from `wp_declarations` (keyed by `document_hash`, which publish doesn't send). Either have publish also upsert a `wp_declarations` row, or have provenance fall back to `wp_notarizations.ai_declaration`, so published-only evidence shows its AI disclosure on the verify page.
