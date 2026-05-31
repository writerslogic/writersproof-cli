# File Signing Feature — SPEC.md

## Overview

Add a universal file signing feature to WritersProof that allows users to drag-and-drop any file, sign it with a C2PA manifest and W3C Verifiable Credential, and receive a single output file. This is completely separate from the authorship evidence/process witnessing feature.

## Target Platforms

1. **writersproof.com** — New `/sign` page in `apps/web`
2. **WritersProof macOS app** — New signing view in the popover
3. **verify.writersproof.com** — Update to handle Reverse Sidecar Container extraction

## Architecture

### Signing Pipeline (client-side, no WASM)

All signing happens in the browser using the existing TypeScript crypto stack:
- `@noble/ed25519` for Ed25519 signing (already in `@writersproof/crypto`)
- `crypto.subtle` for SHA-256 hashing (Web Crypto API)
- Pure TS JUMBF encoder (new, modeled on verify app's decoder)
- Pure TS COSE_Sign1 builder (new, signing counterpart to verify app's verifier)
- Pure TS Reverse Sidecar Container encoder (per writerslogic.com/protocol/reverse-sidecar-v1/)

The signing key is derived from the user's Supabase session. For anonymous/free-tier signing, an ephemeral Ed25519 keypair is generated in-browser.

### Output Strategy

| File Format | Strategy | Output |
|---|---|---|
| PDF | Native C2PA embedding (incremental update) | `filename.pdf` (manifest embedded) |
| JPEG, PNG | Native C2PA embedding (APP11 / caBX) | `filename.jpg` / `filename.png` |
| Everything else | Reverse Sidecar Container | `filename.ext.c2pa` (single file) |

### Verification

The verify app already parses JUMBF and verifies C2PA manifests. It needs:
- Reverse Sidecar detection (`wlas` UUID scan)
- Asset extraction + "Download Original" button
- Display of standalone signing assertions (no process-proof assertions present)

## Deliverables

### 1. `packages/crypto` — Signing primitives

New exports in `@writersproof/crypto`:
- `buildJumbf(manifest)` — JUMBF encoder (ISO 19566-5 box writer)
- `buildCoseSign1(payload, signingKey, certDer?)` — COSE_Sign1 envelope builder
- `buildStandaloneManifest(docHash, filename, mime, signingKey, vc?)` — C2PA manifest builder
- `buildReverseSidecar(jumbf, assetBytes, filename, mime)` — Reverse Sidecar Container encoder
- `embedInPdf(pdfBytes, jumbf)` — PDF incremental update with C2PA stream
- `generateSigningCredential(docHash, filename, signerDid, signingKey)` — W3C VC 2.0 builder

### 2. `apps/web` — `/sign` page

New route and page component:
- Drag-and-drop zone accepting any file
- File info display (name, size, type, SHA-256 preview)
- "Sign" button — signs with C2PA manifest + VC
- Progress indicator during signing
- Download signed file button
- Option to anchor hash on WritersProof API (paid tier)

UI patterns: match existing design system (dark mode, teal accents, rounded-xl cards, border-white/10).

### 3. `apps/verify` — Reverse Sidecar support

Update verification pipeline:
- Detect Reverse Sidecar Container (`wlas` UUID in JUMBF boxes)
- Extract and verify encapsulated asset (SHA-256 check)
- Show "Download Original" button
- Handle manifests without process-proof assertions (standalone signing)

### 4. Rust `authorproof-protocol` — Already done

- `StandaloneManifestBuilder` (c2pa/standalone.rs) — DONE
- `build_reverse_sidecar` / `extract_asset` / `is_reverse_sidecar` (c2pa/container.rs) — DONE

### 5. macOS app — Signing view (deferred to separate session)

New `FileSigningView` in the popover with drag-and-drop, calling FFI functions for standalone signing. Requires new FFI symbols and UniFFI regeneration. Deferred because it requires the full macOS build pipeline.

## Constraints

- No WASM (the authorproof-protocol wasm feature is incomplete — missing wasm-bindgen dep, getrandom js feature, chrono wasmbind)
- Client-side signing only (files never leave the browser)
- Match existing code patterns in each app (Tailwind v4, React 19, Hono, etc.)
- No new npm dependencies beyond what's already in the monorepo
- Anchoring endpoint is a paid feature (check subscription tier before allowing)

## Non-Goals

- JPEG/PNG native embedding (complex format-specific work, defer to later)
- WASM signing pipeline (fix deps later, swap in when ready)
- macOS app view (separate session, requires Xcode build)
- C2PA conformance program membership (parallel business effort)
