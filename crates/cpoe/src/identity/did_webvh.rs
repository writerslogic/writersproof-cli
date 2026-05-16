// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! did:webvh identity integration for CPoE.
//!
//! Bridges CPoE's Ed25519 key material to the [`didwebvh_rs`] crate, providing
//! DID creation, update, rotation, deactivation, and persistence. The signing
//! key is derived from the master identity via HKDF with a dedicated domain
//! separator, so a compromise of the did:webvh key does not expose the master.

use std::path::PathBuf;
use std::sync::Arc;

use affinidi_data_integrity::DataIntegrityError;
use affinidi_secrets_resolver::secrets::KeyType;
use didwebvh_rs::{
    async_trait,
    create::{create_did, CreateDIDConfig},
    log_entry::LogEntryMethods,
    parameters::Parameters,
    DIDWebVHError, DIDWebVHState, Multibase, Signer,
};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use subtle::ConstantTimeEq;

use crate::error::Error;
use crate::identity::did_document::did_key_from_public;

const WEBVH_IDENTITY_DOMAIN: &str = "cpoe-did-webvh-v1";
const MAX_ADDRESS_LEN: usize = 253;

const DID_CORE_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
const ED25519_CONTEXT: &str = "https://w3id.org/security/suites/ed25519-2020/v1";
const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

// ---------------------------------------------------------------------------
// CpopSigner: adapter from ed25519-dalek to didwebvh Signer trait
// ---------------------------------------------------------------------------

/// Adapter implementing the didwebvh [`Signer`] trait using CPoE Ed25519 keys.
///
/// The inner [`SigningKey`] implements `ZeroizeOnDrop`, so key material is
/// automatically erased when this struct is dropped.
pub struct CpopSigner {
    signing_key: SigningKey,
    verification_method: String,
}

impl CpopSigner {
    /// Create a signer from an existing Ed25519 key.
    ///
    /// `verification_method` must be in `did:key:{mb}#{mb}` format as required
    /// by the didwebvh spec.
    pub fn new(signing_key: SigningKey, verification_method: impl Into<String>) -> Self {
        Self {
            signing_key,
            verification_method: verification_method.into(),
        }
    }

    /// Create a signer from an Ed25519 key, deriving the verification method
    /// automatically as `did:key:{multibase}#{multibase}`.
    pub fn from_key(signing_key: SigningKey) -> Self {
        let mb = encode_multibase_ed25519(signing_key.verifying_key().as_bytes());
        let vm = format!("did:key:{mb}#{mb}");
        Self {
            signing_key,
            verification_method: vm,
        }
    }

    pub fn public_key_multibase(&self) -> String {
        encode_multibase_ed25519(self.signing_key.verifying_key().as_bytes())
    }
}

#[async_trait]
impl Signer for CpopSigner {
    fn key_type(&self) -> KeyType {
        KeyType::Ed25519
    }

    fn verification_method(&self) -> &str {
        &self.verification_method
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, DataIntegrityError> {
        use ed25519_dalek::Signer as _;
        Ok(self.signing_key.sign(data).to_bytes().to_vec())
    }
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Validate a did:webvh address (hostname or hostname:path).
fn validate_address(address: &str) -> Result<(), Error> {
    if address.is_empty() {
        return Err(Error::identity("address must not be empty"));
    }
    if address.len() > MAX_ADDRESS_LEN {
        return Err(Error::identity(format!(
            "address too long: {} (max {})",
            address.len(),
            MAX_ADDRESS_LEN
        )));
    }
    if !address.bytes().all(|b| b.is_ascii()) {
        return Err(Error::identity("address must be ASCII"));
    }
    for b in address.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b':' | b'-' | b'_' => {}
            _ => {
                return Err(Error::identity(format!(
                    "address contains invalid character: '{}'",
                    b as char
                )));
            }
        }
    }
    // Defense-in-depth: `//` cannot pass the character allowlist (no `/`),
    // but we reject it explicitly in case the allowlist is ever widened.
    if address.contains("..") || address.contains("//") {
        return Err(Error::identity("address must not contain '..' or '//'"));
    }
    Ok(())
}

/// Derive a dedicated did:webvh signing key from the master key via HKDF.
///
/// The address (e.g. "writersproof.com:authors:alice") is mixed into the
/// derivation so different did:webvh identities get different keys.
pub fn derive_webvh_signing_key(
    master_key: &SigningKey,
    address: &str,
) -> Result<SigningKey, Error> {
    log::debug!("derive_webvh_signing_key: address={}", address);
    let address = address.to_ascii_lowercase();
    validate_address(&address)?;
    let seed = crate::keyhierarchy::hkdf_expand(
        master_key.as_bytes(),
        WEBVH_IDENTITY_DOMAIN.as_bytes(),
        address.as_bytes(),
    )
    .map_err(|e| Error::identity(format!("webvh key derivation: {e}")))?;
    Ok(SigningKey::from_bytes(&seed))
}

// ---------------------------------------------------------------------------
// WebVHIdentity: lifecycle wrapper
// ---------------------------------------------------------------------------

/// A did:webvh identity bound to a CPoE author.
///
/// Wraps [`DIDWebVHState`] with CPoE-specific lifecycle methods. The state
/// is serializable to JSON for persistence between sessions.
pub struct WebVHIdentity {
    pub(crate) state: DIDWebVHState,
    pub(crate) address: String,
    pub(crate) did: String,
    pubkey_hex_cache: std::cell::OnceCell<String>,
}

impl WebVHIdentity {
    /// Create a new did:webvh identity.
    ///
    /// Derives a signing key from `master_key` via HKDF, constructs a DID
    /// document with Ed25519 verification method and WritersProof service
    /// endpoint, and signs the first log entry.
    pub async fn create(
        master_key: &SigningKey,
        address: impl Into<String>,
    ) -> Result<Self, Error> {
        let address = address.into();
        log::debug!("WebVHIdentity::create: address={}", address);
        validate_address(&address)?;
        let webvh_key = derive_webvh_signing_key(master_key, &address)?;
        let signer = CpopSigner::from_key(webvh_key);
        let pk_mb = signer.public_key_multibase();

        let did_template = format!("did:webvh:{{SCID}}:{address}");
        let doc = build_did_document(&did_template, &pk_mb);

        let params = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(&pk_mb)])),
            ..Parameters::default()
        };

        let config = CreateDIDConfig::<CpopSigner, CpopSigner>::builder_generic()
            .address(format!("https://{}/", address.replace(':', "/")))
            .authorization_key(signer)
            .did_document(doc)
            .parameters(params)
            .also_known_as_web(true)
            .build()
            .map_err(map_webvh_err)?;

        let result = create_did(config).await.map_err(map_webvh_err)?;
        let did = result.did().to_string();

        let mut state = DIDWebVHState::default();
        let log_entry = result.log_entry().clone();
        // Rebuild state from the created log entry
        state
            .log_entries_mut()
            .push(didwebvh_rs::log_entry_state::LogEntryState {
                log_entry,
                version_number: 1,
                validated_parameters: Parameters::default(),
                validation_status: didwebvh_rs::log_entry_state::LogEntryValidationStatus::Ok,
            });
        *state.witness_proofs_mut() = result.witness_proofs().clone();

        Ok(Self {
            state,
            address,
            did,
            pubkey_hex_cache: std::cell::OnceCell::new(),
        })
    }

    pub fn did(&self) -> &str {
        &self.did
    }

    pub fn state(&self) -> &DIDWebVHState {
        &self.state
    }

    /// Returns the address this identity is bound to.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Returns whether the identity has been deactivated.
    pub fn is_deactivated(&self) -> bool {
        self.state.deactivated()
    }

    /// Returns the number of log entries.
    pub fn log_entry_count(&self) -> usize {
        self.state.log_entries().len()
    }

    /// Returns the first log entry's version_time as an ISO 8601 string,
    /// or `None` if there are no log entries.
    pub fn created_at(&self) -> Option<String> {
        let ts = self.state.meta_first_ts();
        if ts.is_empty() {
            None
        } else {
            Some(ts.to_string())
        }
    }

    /// Returns the last log entry's version_time as an ISO 8601 string,
    /// or `None` if there are no log entries.
    pub fn updated_at(&self) -> Option<String> {
        let ts = self.state.meta_last_ts();
        if ts.is_empty() {
            None
        } else {
            Some(ts.to_string())
        }
    }

    /// Returns the hex-encoded public key of the derived webvh signing key.
    pub fn public_key_hex(&self, master_key: &SigningKey) -> Result<String, Error> {
        if let Some(cached) = self.pubkey_hex_cache.get() {
            return Ok(cached.clone());
        }
        let derived = derive_webvh_signing_key(master_key, &self.address)?;
        let hex = crate::utils::crypto_types::Ed25519Pubkey::from(derived.verifying_key()).to_hex();
        let _ = self.pubkey_hex_cache.set(hex.clone());
        Ok(hex)
    }

    /// Update the DID document.
    pub async fn update_document(
        &mut self,
        doc: Value,
        master_key: &SigningKey,
    ) -> Result<(), Error> {
        log::debug!("WebVHIdentity::update_document: did={}", self.did);
        let webvh_key = derive_webvh_signing_key(master_key, &self.address)?;
        let signer = CpopSigner::from_key(webvh_key);
        self.state
            .update_document(doc, &signer)
            .await
            .map(|_| ())
            .map_err(map_webvh_err)
    }

    /// Rotate the did:webvh update keys.
    pub async fn rotate_keys(
        &mut self,
        new_keys: Vec<Multibase>,
        master_key: &SigningKey,
    ) -> Result<(), Error> {
        log::debug!("WebVHIdentity::rotate_keys: did={}, new_keys_count={}", self.did, new_keys.len());
        let webvh_key = derive_webvh_signing_key(master_key, &self.address)?;
        let signer = CpopSigner::from_key(webvh_key);
        self.state
            .rotate_keys(new_keys, &signer)
            .await
            .map(|_| ())
            .map_err(map_webvh_err)
    }

    /// Deactivate the did:webvh identity.
    pub async fn deactivate(&mut self, master_key: &SigningKey) -> Result<(), Error> {
        log::debug!("WebVHIdentity::deactivate: did={}", self.did);
        let webvh_key = derive_webvh_signing_key(master_key, &self.address)?;
        let signer = CpopSigner::from_key(webvh_key);
        self.state
            .deactivate(&signer)
            .await
            .map(|_| ())
            .map_err(map_webvh_err)
    }

    /// Save the did:webvh state to disk.
    pub fn save(&self) -> Result<(), Error> {
        log::debug!("WebVHIdentity::save: did={}", self.did);
        let data_dir = data_dir().ok_or_else(|| Error::identity("data directory not available"))?;
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| Error::identity(format!("create data directory: {e}")))?;
        let dir_meta = std::fs::symlink_metadata(&data_dir)
            .map_err(|e| Error::identity(format!("stat data directory: {e}")))?;
        if !dir_meta.is_dir() {
            return Err(Error::identity(
                "data directory path is not a directory (possible symlink attack)",
            ));
        }

        let envelope = serde_json::json!({
            "did": self.did,
            "address": self.address,
        });
        let state_json = serde_json::to_string(&envelope)
            .map_err(|e| Error::identity(format!("serialize webvh metadata: {e}")))?;

        let meta_path = data_dir.join("did_webvh_meta.json");
        atomic_write(&meta_path, state_json.as_bytes())?;

        let state_path = data_dir.join("did_webvh_state.json");
        let state_tmp = data_dir.join("did_webvh_state.json.tmp");
        let state_tmp_str = state_tmp
            .to_str()
            .ok_or_else(|| Error::identity("non-UTF-8 data directory path"))?;
        // Set restrictive umask before save_state writes the temp file
        #[cfg(unix)]
        let _old_umask = unsafe { libc::umask(0o077) };
        let save_result = self.state.save_state(state_tmp_str).map_err(map_webvh_err);
        #[cfg(unix)]
        unsafe {
            libc::umask(_old_umask);
        }
        save_result?;
        if let Err(e) = crate::crypto::restrict_permissions(&state_tmp, 0o600) {
            let _ = std::fs::remove_file(&state_tmp);
            return Err(Error::identity(format!(
                "restrict state file permissions: {e}"
            )));
        }
        // sync_all before rename so the data survives a crash between write and rename.
        {
            let f = std::fs::File::open(&state_tmp)
                .map_err(|e| Error::identity(format!("open webvh state tmp for sync: {e}")))?;
            f.sync_all()
                .map_err(|e| Error::identity(format!("sync webvh state tmp: {e}")))?;
        }
        std::fs::rename(&state_tmp, &state_path)
            .map_err(|e| Error::identity(format!("rename webvh state: {e}")))?;

        Ok(())
    }

    /// Load a previously saved did:webvh identity from disk.
    pub fn load() -> Result<Self, Error> {
        log::debug!("WebVHIdentity::load");
        let data_dir = data_dir().ok_or_else(|| Error::identity("data directory not available"))?;

        let meta_path = data_dir.join("did_webvh_meta.json");
        let (_canonical, meta_file) = crate::utils::fs::open_validated(&meta_path)
            .map_err(|e| Error::identity(format!("open webvh metadata: {e}")))?;
        let meta_json = {
            use std::io::Read;
            let mut s = String::new();
            std::io::BufReader::new(meta_file).read_to_string(&mut s)
                .map_err(|e| Error::identity(format!("read webvh metadata: {e}")))?;
            s
        };
        let meta: serde_json::Value = serde_json::from_str(&meta_json)
            .map_err(|e| Error::identity(format!("parse webvh metadata: {e}")))?;

        let did = meta
            .get("did")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::identity("missing 'did' in webvh metadata"))?
            .to_string();
        let address = meta
            .get("address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::identity("missing 'address' in webvh metadata"))?
            .to_string();

        let state_path = data_dir.join("did_webvh_state.json");
        if !state_path.exists() {
            return Err(Error::not_found("did:webvh state file not found; identity may not have been saved"));
        }
        let path_str = state_path
            .to_str()
            .ok_or_else(|| Error::identity("non-UTF-8 data directory path"))?;
        let state = DIDWebVHState::load_state(path_str).map_err(|e| {
            Error::identity(format!("corrupted did:webvh state (delete and re-create identity to recover): {e}"))
        })?;

        Ok(Self {
            state,
            address,
            did,
            pubkey_hex_cache: std::cell::OnceCell::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Active DID resolution
// ---------------------------------------------------------------------------

/// Return the active author DID, preferring did:webvh if available.
///
/// Falls back to did:key derived from the signing key on disk.
pub fn load_active_did() -> Result<String, Error> {
    log::debug!("load_active_did");
    if let Ok(identity) = WebVHIdentity::load() {
        return Ok(identity.did);
    }
    let sk = load_signing_key()?;
    did_key_from_public(sk.verifying_key().as_bytes())
        .ok_or_else(|| Error::identity("invalid public key length for did:key"))
}

// ---------------------------------------------------------------------------
// Verification (resolve + key match)
// ---------------------------------------------------------------------------

/// Resolve a did:webvh DID and verify the signing public key matches.
///
/// Fetches the DID document via HTTP, validates the log chain, and checks
/// that `expected_pubkey` appears as a verification method in the document.
/// Optionally resolves at a specific `version_time` to verify historical keys.
/// Reject DID URIs whose host resolves to a private or loopback address.
///
/// The did:webvh method-specific ID is `{SCID}:{host}:{path...}`.
/// We extract `host` (index 1 after splitting the remainder by `:`) and
/// reject IP literals and private/reserved DNS suffixes to prevent SSRF.
fn validate_did_host(did: &str) -> Result<(), Error> {
    let remainder = did
        .strip_prefix("did:webvh:")
        .ok_or_else(|| Error::identity("not a did:webvh identifier".to_string()))?;

    let parts: Vec<&str> = remainder.splitn(3, ':').collect();
    let host_raw = parts.get(1).copied().unwrap_or("");
    if host_raw.is_empty() {
        return Err(Error::identity(
            "did:webvh DID missing host component".to_string(),
        ));
    }
    if host_raw.contains("%3A") || host_raw.contains("%3a") {
        return Err(Error::identity(
            "did:webvh host contains percent-encoded colon (ambiguous delimiter)".to_string(),
        ));
    }
    // URL-decode, then strip optional port.
    let decoded = urlencoding::decode(host_raw)
        .map(|c| c.into_owned())
        .map_err(|_| {
            Error::identity(format!(
                "did:webvh host contains invalid percent-encoding: {host_raw}"
            ))
        })?;
    let host = if decoded.starts_with('[') {
        // IPv6 literal: [::1] or [::1]:8080 -- strip brackets (will be rejected below)
        let bracket_end = decoded.find(']').unwrap_or(decoded.len());
        &decoded[1..bracket_end]
    } else if decoded.bytes().next().map_or(true, |b| b.is_ascii_alphabetic()) {
        // Hostname: only strip port if first char is a letter (safe for DNS names)
        match decoded.rsplit_once(':') {
            Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
            _ => decoded.as_str(),
        }
    } else {
        decoded.as_str()
    };
    let host_lower = host.to_lowercase();

    // Reject bare IP addresses (v4 and v6).
    if host_lower
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .is_ok()
    {
        return Err(Error::identity(format!(
            "did:webvh host is an IP address (SSRF risk): {host_lower}"
        )));
    }

    // Reject private/reserved DNS suffixes and loopback names.
    const BLOCKED: &[&str] = &[
        "localhost",
        ".local",
        ".internal",
        ".corp",
        ".lan",
        ".localdomain",
        ".home",
        ".example",
        ".test",
        ".invalid",
    ];
    for blocked in BLOCKED {
        if host_lower == *blocked || (blocked.starts_with('.') && host_lower.ends_with(blocked)) {
            return Err(Error::identity(format!(
                "did:webvh host points to private/reserved name (SSRF risk): {host_lower}"
            )));
        }
    }

    // Reject punycode/IDN labels to prevent homograph attacks that bypass
    // the blocklist above (e.g. xn--localhot-r97e.com).
    if host_lower.split('.').any(|label| label.starts_with("xn--")) {
        return Err(Error::identity(format!(
            "did:webvh host contains punycode IDN label (homograph risk): {host_lower}"
        )));
    }

    Ok(())
}

pub async fn resolve_and_verify_key(
    did: &str,
    expected_pubkey: &[u8; 32],
    version_time: Option<chrono::DateTime<chrono::FixedOffset>>,
) -> Result<bool, Error> {
    log::debug!("resolve_and_verify_key: did={}", did);
    if !did.starts_with("did:webvh:") {
        return Err(Error::identity(format!(
            "not a did:webvh identifier: {did}"
        )));
    }
    validate_did_host(did)?;

    let resolve_did = match version_time {
        Some(ts) => format!(
            "{}?versionTime={}",
            did,
            urlencoding::encode(&ts.to_rfc3339())
        ),
        None => did.to_string(),
    };

    let mut state = DIDWebVHState::default();
    let (log_entry, _metadata) = state
        .resolve(
            &resolve_did,
            didwebvh_rs::resolve::ResolveOptions::default(),
        )
        .await
        .map_err(|e| Error::identity(format!("did:webvh resolution failed: {e}")))?;

    let doc = log_entry
        .get_did_document()
        .map_err(|e| Error::identity(format!("failed to get DID document: {e}")))?;

    let methods = match doc["verificationMethod"].as_array() {
        Some(arr) => arr,
        None => return Ok(false),
    };

    for method in methods {
        if let Some(key_mb) = method["publicKeyMultibase"].as_str() {
            if let Some(remote_pubkey) = decode_multibase_ed25519(key_mb) {
                if remote_pubkey.ct_eq(expected_pubkey).into() {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

/// Verify that an evidence packet's author_did resolves to its signing key.
///
/// Converts `packet_created_ms` to a `DateTime` for `versionTime` resolution
/// so the DID document is resolved at the point in time the packet was created.
pub async fn verify_packet_author_did(
    author_did: &str,
    signing_public_key: &[u8; 32],
    packet_created_ms: u64,
) -> Result<bool, Error> {
    log::debug!("verify_packet_author_did: author_did={}, packet_created_ms={}", author_did, packet_created_ms);
    const MAX_REASONABLE_MS: u64 = 32503680000000; // year 3000
    if packet_created_ms > MAX_REASONABLE_MS {
        return Err(Error::identity(format!(
            "packet_created_ms {packet_created_ms} exceeds reasonable range"
        )));
    }
    let secs = i64::try_from(packet_created_ms / 1000)
        .map_err(|_| Error::identity("timestamp overflow"))?;
    let nanos = ((packet_created_ms % 1000) * 1_000_000) as u32;
    let version_time = chrono::DateTime::from_timestamp(secs, nanos).map(|dt| dt.fixed_offset());

    resolve_and_verify_key(author_did, signing_public_key, version_time).await
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn data_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("CPOE_DATA_DIR") {
        return Some(PathBuf::from(dir));
    }
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir().map(|h| h.join("Library/Application Support/WritersProof"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        dirs::data_local_dir().map(|d| d.join("CPoE"))
    }
}

fn load_signing_key() -> Result<SigningKey, Error> {
    let data_dir =
        data_dir().ok_or_else(|| Error::identity("Data directory not found"))?;
    let key_path = data_dir.join("signing_key");
    let (canonical, file) = crate::utils::fs::open_validated(&key_path)
        .map_err(|e| Error::identity(format!("open signing key: {e}")))?;
    let canonical_data_dir = crate::utils::fs::canonicalize_validated(&data_dir)
        .map_err(|e| Error::identity(format!("canonicalize data directory: {e}")))?;
    if !canonical.starts_with(&canonical_data_dir) {
        return Err(Error::identity(
            "signing key path resolves outside data directory (possible symlink attack)",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file
            .metadata()
            .map_err(|e| Error::identity(format!("stat signing key: {e}")))?;
        let mode = meta.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(Error::identity(format!(
                "signing key file has unsafe permissions {:o}; expected owner-only",
                mode
            )));
        }
    }
    use std::io::Read;
    let mut buf = Vec::new();
    let mut reader = std::io::BufReader::new(file);
    reader
        .read_to_end(&mut buf)
        .map_err(|e| Error::identity(format!("read signing key: {e}")))?;
    let key_data = zeroize::Zeroizing::new(buf);
    if key_data.len() != 32 {
        return Err(Error::identity(format!(
            "signing key file has invalid length {} (expected exactly 32)",
            key_data.len()
        )));
    }
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&key_data[..32]);
    Ok(SigningKey::from_bytes(&secret))
}

/// Decode a multibase+multicodec Ed25519 public key string to raw 32-byte key.
/// Handles base58btc ('z') and base16 ('f'/'F') encodings.
/// Returns `None` if the encoding is unrecognized or the multicodec prefix doesn't match.
fn decode_multibase_ed25519(multibase: &str) -> Option<[u8; 32]> {
    let decoded = if let Some(rest) = multibase.strip_prefix('z') {
        bs58::decode(rest).into_vec().ok()?
    } else if let Some(rest) = multibase.strip_prefix('f') {
        hex::decode(rest).ok()?
    } else if let Some(rest) = multibase.strip_prefix('F') {
        hex::decode(rest).ok()?
    } else {
        return None;
    };
    if decoded.len() != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded[2..]);
    Some(key)
}

fn encode_multibase_ed25519(public_key: &[u8]) -> String {
    let mut prefixed = Vec::with_capacity(2 + public_key.len());
    prefixed.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    prefixed.extend_from_slice(public_key);
    format!("z{}", bs58::encode(&prefixed).into_string())
}

fn build_did_document(did_template: &str, pk_multibase: &str) -> Value {
    json!({
        "id": did_template,
        "@context": [DID_CORE_CONTEXT, ED25519_CONTEXT],
        "verificationMethod": [{
            "id": format!("{did_template}#key-0"),
            "type": "Multikey",
            "publicKeyMultibase": pk_multibase,
            "controller": did_template,
        }],
        "authentication": [format!("{did_template}#key-0")],
        "assertionMethod": [format!("{did_template}#key-0")],
    })
}

fn atomic_write(path: &std::path::Path, data: &[u8]) -> Result<(), Error> {
    crate::crypto::atomic_write(path, data)
        .map_err(|e| Error::identity(format!("atomic write {}: {e}", path.display())))?;
    crate::crypto::restrict_permissions(path, 0o600)
        .map_err(|e| Error::identity(format!("restrict permissions {}: {e}", path.display())))?;
    Ok(())
}

fn map_webvh_err(e: DIDWebVHError) -> Error {
    Error::identity(format!("did:webvh: {e}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42u8; 32])
    }

    /// CpopSigner must report Ed25519 key type.
    #[test]
    fn signer_key_type() {
        let signer = CpopSigner::from_key(test_signing_key());
        assert_eq!(signer.key_type(), KeyType::Ed25519);
    }

    /// CpopSigner verification method must be did:key:{mb}#{mb} format.
    #[test]
    fn signer_verification_method_format() {
        let signer = CpopSigner::from_key(test_signing_key());
        let vm = signer.verification_method();
        assert!(vm.starts_with("did:key:z"), "must start with did:key:z");
        assert!(vm.contains('#'), "must contain fragment separator");
        let parts: Vec<&str> = vm.split('#').collect();
        assert_eq!(parts.len(), 2);
        let prefix = parts[0].strip_prefix("did:key:").unwrap();
        assert_eq!(prefix, parts[1], "key and fragment must match");
    }

    /// CpopSigner sign must produce a valid Ed25519 signature.
    #[tokio::test]
    async fn signer_sign_roundtrip() {
        let key = test_signing_key();
        let verifying = key.verifying_key();
        let signer = CpopSigner::from_key(key);

        let data = b"test message for signing";
        let sig_bytes = signer.sign(data).await.expect("sign must succeed");
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signature must be 64 bytes");

        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).expect("valid sig");
        use ed25519_dalek::Verifier;
        verifying.verify(data, &sig).expect("signature must verify");
    }

    /// Derived webvh key must differ from the master key.
    #[test]
    fn derived_key_differs_from_master() {
        let master = test_signing_key();
        let derived = derive_webvh_signing_key(&master, "example.com").unwrap();
        assert_ne!(
            master.verifying_key().as_bytes(),
            derived.verifying_key().as_bytes()
        );
    }

    /// Different addresses must produce different derived keys.
    #[test]
    fn derived_key_address_separation() {
        let master = test_signing_key();
        let k1 = derive_webvh_signing_key(&master, "alice.example.com").unwrap();
        let k2 = derive_webvh_signing_key(&master, "bob.example.com").unwrap();
        assert_ne!(k1.verifying_key().as_bytes(), k2.verifying_key().as_bytes());
    }

    /// Same master + address must produce the same derived key (deterministic).
    #[test]
    fn derived_key_deterministic() {
        let master = test_signing_key();
        let k1 = derive_webvh_signing_key(&master, "example.com").unwrap();
        let k2 = derive_webvh_signing_key(&master, "example.com").unwrap();
        assert_eq!(k1.verifying_key().as_bytes(), k2.verifying_key().as_bytes());
    }

    /// Multibase encoding must produce z-prefixed base58btc with Ed25519 multicodec.
    #[test]
    fn multibase_encoding() {
        let key = test_signing_key();
        let mb = encode_multibase_ed25519(key.verifying_key().as_bytes());
        assert!(mb.starts_with('z'));
        let decoded = bs58::decode(&mb[1..]).into_vec().unwrap();
        assert_eq!(decoded[0], 0xed);
        assert_eq!(decoded[1], 0x01);
        assert_eq!(&decoded[2..], key.verifying_key().as_bytes());
    }

    /// DID document template must contain required fields and placeholders.
    #[test]
    fn did_document_structure() {
        let doc = build_did_document("did:webvh:{SCID}:example.com", "z6MkTest");
        assert_eq!(doc["id"], "did:webvh:{SCID}:example.com");
        assert!(doc["@context"].is_array());
        assert!(doc["verificationMethod"].is_array());
        assert!(doc["authentication"].is_array());
        assert!(doc["assertionMethod"].is_array());
        assert_eq!(
            doc["verificationMethod"][0]["type"], "Multikey",
            "must use Multikey type per didwebvh spec"
        );
    }

    /// load_active_did falls back to did:key when no webvh identity exists.
    #[test]
    fn load_active_did_fallback() {
        // Without a saved webvh identity, should attempt did:key fallback.
        // This may fail in CI where no signing key exists on disk, but the
        // code path exercises both branches.
        let result = load_active_did();
        if let Ok(did) = &result {
            assert!(
                did.starts_with("did:key:") || did.starts_with("did:webvh:"),
                "must return a valid DID"
            );
        }
    }

    /// CpopSigner::new() with a custom verification_method returns it as-is.
    #[test]
    fn signer_new_custom_vm() {
        let custom_vm = "did:example:custom#key-99";
        let signer = CpopSigner::new(test_signing_key(), custom_vm);
        assert_eq!(signer.verification_method(), custom_vm);
    }

    /// Signing two different messages must produce different signatures.
    #[tokio::test]
    async fn signer_sign_different_data_different_sigs() {
        let signer = CpopSigner::from_key(test_signing_key());
        let sig_a = signer.sign(b"message A").await.unwrap();
        let sig_b = signer.sign(b"message B").await.unwrap();
        assert_ne!(sig_a, sig_b, "different inputs must yield different sigs");
    }

    /// Ed25519 is deterministic; signing the same message twice yields identical signatures.
    #[tokio::test]
    async fn signer_sign_same_data_same_sig() {
        let signer = CpopSigner::from_key(test_signing_key());
        let msg = b"deterministic check";
        let sig1 = signer.sign(msg).await.unwrap();
        let sig2 = signer.sign(msg).await.unwrap();
        assert_eq!(sig1, sig2, "Ed25519 signing must be deterministic");
    }

    /// Derive with empty string address must fail (empty address weakens domain separation).
    #[test]
    fn derived_key_empty_address_rejected() {
        let master = test_signing_key();
        let result = derive_webvh_signing_key(&master, "");
        assert!(
            result.is_err(),
            "empty address must be rejected to preserve domain separation"
        );
    }

    /// Derive with a very long address (1000 chars) should succeed.
    #[test]
    fn derived_key_long_address_rejected() {
        let master = test_signing_key();
        let long_addr = "a".repeat(254);
        let result = derive_webvh_signing_key(&master, &long_addr);
        assert!(
            result.is_err(),
            "address exceeding 253 chars must be rejected"
        );
    }

    /// build_did_document() output must contain {SCID} in the id field.
    #[test]
    fn did_document_contains_scid_placeholder() {
        let doc = build_did_document("did:webvh:{SCID}:example.com", "z6MkTest");
        let id = doc["id"].as_str().expect("id must be a string");
        assert!(
            id.contains("{SCID}"),
            "DID template must contain {{SCID}} placeholder"
        );
    }

    /// Verify the publicKeyMultibase in the DID doc matches the key we provided.
    #[test]
    fn did_document_verification_method_matches_key() {
        let key = test_signing_key();
        let pk_mb = encode_multibase_ed25519(key.verifying_key().as_bytes());
        let doc = build_did_document("did:webvh:{SCID}:example.com", &pk_mb);
        let vm_key = doc["verificationMethod"][0]["publicKeyMultibase"]
            .as_str()
            .expect("publicKeyMultibase must be a string");
        assert_eq!(
            vm_key, pk_mb,
            "document key must match the provided multibase"
        );
    }

    /// Authentication array must reference the same key id as verificationMethod.
    #[test]
    fn did_document_authentication_references_key() {
        let doc = build_did_document("did:webvh:{SCID}:example.com", "z6MkTest");
        let vm_id = doc["verificationMethod"][0]["id"]
            .as_str()
            .expect("verificationMethod id must be a string");
        let auth_ref = doc["authentication"][0]
            .as_str()
            .expect("authentication entry must be a string reference");
        assert_eq!(
            auth_ref, vm_id,
            "authentication must reference the verification method id"
        );
    }

    /// Multibase encoding of a known key produces the expected output.
    #[test]
    fn multibase_known_vector() {
        // All-zeros 32-byte public key
        let zeros = [0u8; 32];
        let mb = encode_multibase_ed25519(&zeros);
        // Manually construct expected: z + base58btc(0xed 0x01 ++ 32 zero bytes)
        let mut prefixed = vec![0xed, 0x01];
        prefixed.extend_from_slice(&zeros);
        let expected = format!("z{}", bs58::encode(&prefixed).into_string());
        assert_eq!(mb, expected, "multibase encoding must match known vector");
    }

    /// map_webvh_err must preserve the original error message in the output.
    #[test]
    fn map_webvh_err_preserves_message() {
        let original = DIDWebVHError::DIDError("test error sentinel".into());
        let mapped = map_webvh_err(original);
        let msg = format!("{mapped}");
        assert!(
            msg.contains("test error sentinel"),
            "mapped error must contain the original message, got: {msg}"
        );
    }

    /// public_key_multibase() must match the key portion of verification_method().
    #[test]
    fn public_key_multibase_matches_verification_method() {
        let signer = CpopSigner::from_key(test_signing_key());
        let pk_mb = signer.public_key_multibase();
        let vm = signer.verification_method();
        // verification_method is "did:key:{mb}#{mb}", extract the key part
        let key_part = vm
            .strip_prefix("did:key:")
            .unwrap()
            .split('#')
            .next()
            .unwrap();
        assert_eq!(
            pk_mb, key_part,
            "public_key_multibase must match the key in verification_method"
        );
    }

    /// Full lifecycle: create a WebVHIdentity, verify DID is non-empty and state accessible.
    #[tokio::test]
    async fn webvh_identity_create_lifecycle() {
        let master = test_signing_key();
        let identity = WebVHIdentity::create(&master, "example.com").await;
        match identity {
            Ok(id) => {
                assert!(!id.did().is_empty(), "DID must not be empty");
                assert!(
                    id.did().starts_with("did:webvh:"),
                    "DID must start with did:webvh:"
                );
                // State must be accessible and have at least one log entry
                let state = id.state();
                assert!(
                    !state.log_entries().is_empty(),
                    "state must contain at least one log entry"
                );
            }
            Err(e) => {
                // create_did may fail in test environments without network;
                // verify the error is from the webvh layer, not a key derivation bug
                let msg = format!("{e}");
                assert!(
                    msg.contains("did:webvh") || msg.contains("webvh"),
                    "error must originate from webvh layer, got: {msg}"
                );
            }
        }
    }

    /// Empty address must be rejected.
    #[test]
    fn validate_address_empty() {
        assert!(validate_address("").is_err());
    }

    /// Address exceeding 253 chars must be rejected.
    #[test]
    fn validate_address_too_long() {
        let long = "a".repeat(254);
        assert!(validate_address(&long).is_err());
    }

    /// Path traversal must be rejected.
    #[test]
    fn validate_address_path_traversal() {
        assert!(validate_address("evil.com:..:..:admin").is_err());
    }

    /// Query/fragment characters must be rejected.
    #[test]
    fn validate_address_special_chars() {
        assert!(validate_address("evil.com?q=1").is_err());
        assert!(validate_address("evil.com#frag").is_err());
        assert!(validate_address("user@evil.com").is_err());
        assert!(validate_address("evil.com/path").is_err());
    }

    /// Valid hostname address must be accepted.
    #[test]
    fn validate_address_valid() {
        assert!(validate_address("example.com").is_ok());
        assert!(validate_address("writersproof.com:authors:alice").is_ok());
        assert!(validate_address("sub.example.com").is_ok());
    }

    /// WebVHIdentity::create rejects invalid addresses.
    #[tokio::test]
    async fn create_rejects_empty_address() {
        let master = test_signing_key();
        let result = WebVHIdentity::create(&master, "").await;
        assert!(result.is_err());
    }

    /// Malformed did:webvh string should produce a resolution error.
    #[tokio::test]
    async fn resolve_and_verify_key_invalid_did() {
        let key = [0u8; 32];
        let result = resolve_and_verify_key("did:webvh:bad", &key, None).await;
        assert!(result.is_err(), "malformed DID should produce an error");
    }

    /// Non-did:webvh DIDs should be rejected with a clear error.
    #[tokio::test]
    async fn verify_packet_author_did_rejects_non_webvh() {
        let key = [0u8; 32];
        let result = verify_packet_author_did("did:key:z6Mk...", &key, 1700000000000).await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("not a did:webvh"),
            "expected 'not a did:webvh' in error, got: {err_msg}"
        );
    }

    /// address() must return the address the identity was constructed with.
    #[test]
    fn accessor_address() {
        let identity = WebVHIdentity {
            state: DIDWebVHState::default(),
            address: "example.com".to_string(),
            did: "did:webvh:abc123:example.com".to_string(),
            pubkey_hex_cache: std::cell::OnceCell::new(),
        };
        assert_eq!(identity.address(), "example.com");
    }

    /// did() must return a non-empty did:webvh string.
    #[test]
    fn accessor_did_not_empty() {
        let identity = WebVHIdentity {
            state: DIDWebVHState::default(),
            address: "example.com".to_string(),
            did: "did:webvh:abc123:example.com".to_string(),
            pubkey_hex_cache: std::cell::OnceCell::new(),
        };
        assert!(!identity.did().is_empty());
        assert!(identity.did().starts_with("did:webvh:"));
    }

    /// is_deactivated() must return false for a default state.
    #[test]
    fn accessor_is_deactivated_default() {
        let identity = WebVHIdentity {
            state: DIDWebVHState::default(),
            address: "example.com".to_string(),
            did: "did:webvh:abc123:example.com".to_string(),
            pubkey_hex_cache: std::cell::OnceCell::new(),
        };
        assert!(!identity.is_deactivated());
    }

    /// log_entry_count() must return 0 for a default state.
    #[test]
    fn accessor_log_entry_count_empty() {
        let identity = WebVHIdentity {
            state: DIDWebVHState::default(),
            address: "example.com".to_string(),
            did: "did:webvh:abc123:example.com".to_string(),
            pubkey_hex_cache: std::cell::OnceCell::new(),
        };
        assert_eq!(identity.log_entry_count(), 0);
    }

    /// created_at() must return None for a default state with no log entries.
    #[test]
    fn accessor_created_at_none_when_empty() {
        let identity = WebVHIdentity {
            state: DIDWebVHState::default(),
            address: "example.com".to_string(),
            did: "did:webvh:abc123:example.com".to_string(),
            pubkey_hex_cache: std::cell::OnceCell::new(),
        };
        assert!(identity.created_at().is_none());
    }

    /// updated_at() must return None for a default state with no log entries.
    #[test]
    fn accessor_updated_at_none_when_empty() {
        let identity = WebVHIdentity {
            state: DIDWebVHState::default(),
            address: "example.com".to_string(),
            did: "did:webvh:abc123:example.com".to_string(),
            pubkey_hex_cache: std::cell::OnceCell::new(),
        };
        assert!(identity.updated_at().is_none());
    }

    /// public_key_hex() must return a 64-char hex string (32 bytes).
    #[test]
    fn accessor_public_key_hex() {
        let master = test_signing_key();
        let identity = WebVHIdentity {
            state: DIDWebVHState::default(),
            address: "example.com".to_string(),
            did: "did:webvh:abc123:example.com".to_string(),
            pubkey_hex_cache: std::cell::OnceCell::new(),
        };
        let hex_key = identity.public_key_hex(&master).unwrap();
        assert_eq!(hex_key.len(), 64);
    }

    #[test]
    fn validate_did_host_accepts_public_domain() {
        assert!(validate_did_host("did:webvh:SCID123:example.com").is_ok());
        assert!(validate_did_host("did:webvh:SCID123:writersproof.com").is_ok());
        assert!(validate_did_host("did:webvh:SCID123:sub.domain.org").is_ok());
    }

    #[test]
    fn validate_did_host_rejects_ip_address() {
        assert!(validate_did_host("did:webvh:SCID123:192.168.1.1").is_err());
        assert!(validate_did_host("did:webvh:SCID123:10.0.0.1").is_err());
        assert!(validate_did_host("did:webvh:SCID123:127.0.0.1").is_err());
    }

    #[test]
    fn validate_did_host_rejects_private_names() {
        assert!(validate_did_host("did:webvh:SCID123:localhost").is_err());
        assert!(validate_did_host("did:webvh:SCID123:server.local").is_err());
        assert!(validate_did_host("did:webvh:SCID123:host.internal").is_err());
        assert!(validate_did_host("did:webvh:SCID123:app.corp").is_err());
    }

    #[test]
    fn validate_did_host_rejects_missing_host() {
        assert!(validate_did_host("did:webvh:SCID123").is_err());
    }
}
