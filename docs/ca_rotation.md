# CA Key Rotation Runbook

This document describes how to rotate the WritersProof attestation CA key used
to sign `BeaconAttestation` records and the trust bundle manifest.

Two constants must stay in sync:

| Location | Purpose |
|---|---|
| `crates/cpoe/src/war/verification.rs` — `CA_KEY_RING` | Compile-time fallback for offline verification |
| `crates/cpoe/src/war/trust_bundle.rs` — `pinned_bundle()` | Compile-time fallback in the trust-bundle loader |

Both must be updated in the same commit.

---

## 1. Generate a New Ed25519 CA Key Pair

```sh
# Generate 32 bytes of key material and base64-encode for storage.
openssl genpkey -algorithm ed25519 -out new_ca_key.pem
openssl pkey -in new_ca_key.pem -pubout -out new_ca_pub.pem

# Extract raw 32-byte private scalar (for signing attestations).
openssl pkey -in new_ca_key.pem -outform DER | tail -c 32 | xxd -p -c 32

# Extract raw 32-byte public key.
openssl pkey -in new_ca_pub.pem -pubin -outform DER | tail -c 32 | xxd -p -c 32
```

Store the private key in the WritersLogic 1Password vault under "WritersProof CA Keys".
Never commit private key material to git.

---

## 2. Compute the Key ID (kid)

The `kid` is the first 8 bytes (16 hex chars) of SHA-256 of the raw public key bytes:

```sh
echo -n "<32-byte-pubkey-hex>" | xxd -r -p | sha256sum | cut -c1-16
```

---

## 3. Choose Validity Window

- `not_before`: the date this key takes effect (ISO 8601 UTC, `Z` suffix).
- `not_after`: 10 years after `not_before` is the standard rotation period.
- Set `not_before` at least **30 days in the future** to allow the binary update
  carrying the new key to propagate before the key is used for signing.

---

## 4. Update `CA_KEY_RING` in `verification.rs`

File: `crates/cpoe/src/war/verification.rs`

Add the new entry **at the front** of `CA_KEY_RING`. Leave all existing entries
in place — removing a key breaks verification for all evidence signed while it
was valid.

```rust
const CA_KEY_RING: &[CaKeyEntry] = &[
    // NEW KEY — add here
    CaKeyEntry {
        kid: "<new-kid-16-hex-chars>",
        pubkey_hex: "<new-pubkey-64-hex-chars>",
        not_before: "YYYY-MM-DDT00:00:00Z",
        not_after:  "YYYY-MM-DDT23:59:59Z",
    },
    // EXISTING KEYS — do not remove until not_after has passed
    CaKeyEntry {
        kid: "e58a2aacaad69b37",
        pubkey_hex: "b48f36054b9160dff06ac4329898523f441914442958a01e84b719ac539ca053",
        not_before: "2026-03-19T00:00:00Z",
        not_after:  "2036-03-18T23:59:59Z",
    },
];
```

---

## 5. Update `pinned_bundle()` in `trust_bundle.rs`

File: `crates/cpoe/src/war/trust_bundle.rs`

Add the new key as the first entry in `pinned_bundle()`. Keep existing entries:

```rust
pub fn pinned_bundle() -> Vec<CaBundleEntry> {
    vec![
        CaBundleEntry {
            kid: "<new-kid>".to_string(),
            pubkey_hex: "<new-pubkey-hex>".to_string(),
            not_before: "YYYY-MM-DDT00:00:00Z".to_string(),
            not_after:  "YYYY-MM-DDT23:59:59Z".to_string(),
        },
        // Previous entry stays:
        CaBundleEntry {
            kid: "e58a2aacaad69b37".to_string(),
            pubkey_hex: "b48f36054b9160dff06ac4329898523f441914442958a01e84b719ac539ca053".to_string(),
            not_before: "2026-03-19T00:00:00Z".to_string(),
            not_after:  "2036-03-18T23:59:59Z".to_string(),
        },
    ]
}
```

---

## 6. Update the Remote Trust Bundle Manifest

The remote manifest lives at the URL configured in `TrustBundleConfig::manifest_url`
(default: `https://trust.writersproof.com/ca-bundle.json`).

### 6a. Build the payload JSON

The `payload` field is canonical JSON of `{version, published_at, keys}`:

```json
{
  "version": 2,
  "published_at": "YYYY-MM-DDTHH:MM:SSZ",
  "keys": [
    {
      "kid": "<new-kid>",
      "pubkey_hex": "<new-pubkey-hex>",
      "not_before": "YYYY-MM-DDT00:00:00Z",
      "not_after": "YYYY-MM-DDT23:59:59Z"
    },
    {
      "kid": "e58a2aacaad69b37",
      "pubkey_hex": "b48f36054b9160dff06ac4329898523f441914442958a01e84b719ac539ca053",
      "not_before": "2026-03-19T00:00:00Z",
      "not_after": "2036-03-18T23:59:59Z"
    }
  ]
}
```

Keys in `payload` must be sorted alphabetically; use `jq --sort-keys`.

### 6b. Sign the payload with the manifest signing key

The manifest signing key is pinned in `MANIFEST_SIGNING_PUBKEY_HEX`
(`trust_bundle.rs`). Its private key is stored in 1Password under
"WritersProof Manifest Signing Key".

```sh
# Sign: output is 64 raw bytes, hex-encode for the manifest.
echo -n '<payload-json>' | openssl pkeyutl -sign -inkey manifest_signing_key.pem \
  | xxd -p -c 64
```

### 6c. Assemble the full manifest JSON

```json
{
  "version": 2,
  "published_at": "...",
  "keys": [...],
  "signature": "<64-byte-sig-hex>",
  "payload": "<payload-json-as-string>"
}
```

### 6d. Deploy to CDN

Upload to `https://trust.writersproof.com/ca-bundle.json` with:
- `Content-Type: application/json`
- `Cache-Control: max-age=3600, s-maxage=3600`

---

## 7. Update `MANIFEST_SIGNING_PUBKEY_HEX` (first-time production setup)

The current value is an all-zeros placeholder that disables manifest signature
verification in development builds. Before deploying to production:

1. Generate a dedicated Ed25519 manifest signing key pair (separate from the CA key).
2. Replace the all-zeros value in `trust_bundle.rs`:

```rust
const MANIFEST_SIGNING_PUBKEY_HEX: &str =
    "<64-hex-chars-of-manifest-signing-pubkey>";
```

3. Store the private key in 1Password under "WritersProof Manifest Signing Key".
4. This key must never be rotated remotely — it is a root of trust pinned in the binary.
   Rotating it requires a binary update (intentional).

---

## 8. Key Removal Policy

A key may be removed from `CA_KEY_RING` and `pinned_bundle()` only when **both**
conditions are met:

1. Its `not_after` date has passed.
2. All evidence packets signed with it have been re-exported or are known expired.

When in doubt, leave old keys in place. Stale keys cannot be used to forge new
attestations (validity window is checked), but are needed to verify old ones.

---

## 9. Verification After Rotation

After updating and deploying:

```sh
cargo test -p cpoe --lib war::
cargo test -p cpoe --lib war::trust_bundle
```

All `test_find_ca_key_*` and `test_find_in_bundle_*` tests must pass.

If adding a new key with future `not_before`, also add a test asserting the key
is NOT valid before `not_before` and IS valid after.
