// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub mod anti_analysis;
pub mod lamport;
pub mod mem;
pub mod obfuscated;
pub use anti_analysis::{harden_process, is_debugger_present};
pub use mem::{ProtectedBuf, ProtectedKey};
pub use obfuscated::{Obfuscated, ObfuscatedString};

/// HMAC-SHA256 type alias used for event and integrity MACs.
pub type HmacSha256 = Hmac<Sha256>;

/// Compute SHA-256 hash of a file via streaming chunked reader.
pub fn hash_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let (hash, _) = hash_file_with_size(path)?;
    Ok(hash)
}

/// Compute SHA-256 hash of a file, returning (hash, bytes_read).
/// Eliminates TOCTOU races vs separate `fs::metadata` call.
/// Rejects files larger than [`MAX_FILE_SIZE`](crate::MAX_FILE_SIZE) to prevent
/// unbounded I/O on oversized inputs.
///
/// For directories (macOS packages like .scriv, .pages), hashes the
/// concatenation of all regular file paths and sizes within the package.
pub fn hash_file_with_size(path: &Path) -> std::io::Result<([u8; 32], u64)> {
    if path.is_dir() {
        return hash_package_dir(path);
    }
    let file = File::open(path)?;
    let len = file.metadata()?.len();
    if len > crate::MAX_FILE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "file size {} exceeds MAX_FILE_SIZE ({})",
                len,
                crate::MAX_FILE_SIZE
            ),
        ));
    }
    hash_file_handle(&file)
}

fn hash_package_dir(dir: &Path) -> std::io::Result<([u8; 32], u64)> {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    let mut total_size: u64 = 0;
    let mut entries: Vec<(String, u64)> = Vec::new();

    fn walk(base: &Path, current: &Path, depth: u8, out: &mut Vec<(String, u64)>) {
        if depth > 5 { return; }
        let Ok(rd) = std::fs::read_dir(current) else { return };
        for entry in rd.flatten() {
            let ft = match entry.file_type() { Ok(t) => t, Err(_) => continue };
            if ft.is_file() {
                let rel = entry.path().strip_prefix(base).unwrap_or(&entry.path()).to_string_lossy().into_owned();
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                out.push((rel, size));
            } else if ft.is_dir() {
                walk(base, &entry.path(), depth + 1, out);
            }
        }
    }

    walk(dir, dir, 0, &mut entries);
    entries.sort();
    for (path, size) in &entries {
        hasher.update(path.as_bytes());
        hasher.update(b":");
        hasher.update(size.to_le_bytes());
        hasher.update(b"\n");
        total_size += size;
    }
    Ok((hasher.finalize().into(), total_size))
}

/// Compute SHA-256 hash from an already-opened file handle, returning (hash, bytes_read).
///
/// The handle is seeked to the start before reading and is NOT consumed,
/// so the caller can hold it open through subsequent operations to prevent
/// TOCTOU races (another process modifying the file between hash and store).
pub fn hash_file_handle(file: &File) -> std::io::Result<([u8; 32], u64)> {
    use std::io::Seek;
    let mut reader = BufReader::new(file);
    reader.seek(std::io::SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut total_bytes: u64 = 0;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
        total_bytes += bytes_read as u64;
    }

    Ok((hasher.finalize().into(), total_bytes))
}

/// Trait for objects that can be updated with event data (hasher, HMAC).
trait EventUpdate {
    fn update_bytes(&mut self, data: &[u8]);
}

impl EventUpdate for Sha256 {
    fn update_bytes(&mut self, data: &[u8]) {
        Digest::update(self, data);
    }
}

impl EventUpdate for HmacSha256 {
    fn update_bytes(&mut self, data: &[u8]) {
        Mac::update(self, data);
    }
}

/// Encapsulates data for a file event to be hashed or MACed.
#[derive(Clone, Debug)]
pub struct EventData {
    pub device_id: [u8; 16],
    pub timestamp_ns: i64,
    pub file_path: String,
    pub content_hash: [u8; 32],
    pub file_size: i64,
    pub size_delta: i32,
    pub previous_hash: [u8; 32],
}

fn update_event_common<U: EventUpdate>(u: &mut U, data: &EventData) {
    u.update_bytes(b"cpoe-event-v2");
    u.update_bytes(&data.device_id);
    u.update_bytes(&data.timestamp_ns.to_be_bytes());
    let path_bytes = data.file_path.as_bytes();
    u.update_bytes(&(path_bytes.len() as u64).to_be_bytes());
    u.update_bytes(path_bytes);
    u.update_bytes(&data.content_hash);
    u.update_bytes(&data.file_size.to_be_bytes());
    u.update_bytes(&data.size_delta.to_be_bytes());
    u.update_bytes(&data.previous_hash);
}

/// Compute SHA-256 chain hash for a file event with domain separation.
pub fn compute_event_hash(data: &EventData) -> [u8; 32] {
    let mut hasher = Sha256::new();
    update_event_common(&mut hasher, data);
    hasher.finalize().into()
}

/// Compute HMAC-SHA256 integrity tag for a file event.
pub fn compute_event_hmac(key: &[u8], data: &EventData) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC-SHA256 accepts any key size; this is infallible");
    update_event_common(&mut mac, data);
    mac.finalize().into_bytes().into()
}

/// Compute HMAC-SHA256 integrity tag over chain hash, event count, and last verified sequence.
pub fn compute_integrity_hmac(
    key: &[u8],
    chain_hash: &[u8; 32],
    event_count: i64,
    last_verified_sequence: i64,
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC-SHA256 accepts any key size; this is infallible");
    mac.update(b"cpoe-integrity-v1");
    mac.update(chain_hash);
    mac.update(&event_count.to_be_bytes());
    mac.update(&last_verified_sequence.to_be_bytes());

    mac.finalize().into_bytes().into()
}

/// Derive an HMAC key from a private key seed via SHA-256 with domain separation.
///
/// NOTE: This intentionally uses SHA-256 rather than HKDF for backwards compatibility
/// with existing HMAC chains. Changing to HKDF would invalidate all previously stored
/// event integrity tags.
pub fn derive_hmac_key(priv_key_seed: &[u8]) -> Zeroizing<Vec<u8>> {
    assert!(priv_key_seed.len() >= 16, "derive_hmac_key: seed must be ≥16 bytes");
    let mut hasher = Sha256::new();
    hasher.update(b"cpoe-hmac-key-v1");
    hasher.update(priv_key_seed);
    Zeroizing::new(hasher.finalize().to_vec())
}

/// Derive a purpose-specific HMAC key from a signing key via HKDF-SHA256.
///
/// Each purpose gets a cryptographically independent key, so compromising one
/// store's HMAC key does not affect the others. The `purpose` string is used
/// as the HKDF info parameter for domain separation.
pub fn derive_hmac_key_for_purpose(
    signing_key: &ed25519_dalek::SigningKey,
    purpose: &str,
) -> Zeroizing<Vec<u8>> {
    let mut key_bytes = Zeroizing::new(signing_key.to_bytes().to_vec());
    let hk = Hkdf::<Sha256>::new(Some(b"cpoe-hmac-key-derive-v2"), &key_bytes);
    let mut okm = Zeroizing::new(vec![0u8; 32]);
    hk.expand(purpose.as_bytes(), &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key_bytes.zeroize();
    okm
}

/// Derive PRK per draft-condrey-rats-pop §5.3:
///   PRK = HKDF-Extract(salt="PoP-key-derivation-v1", IKM=merkle-root || input)
fn derive_pop_prk(merkle_root: &[u8], swf_input: &[u8]) -> Hkdf<Sha256> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(merkle_root.len() + swf_input.len()));
    ikm.extend_from_slice(merkle_root);
    ikm.extend_from_slice(swf_input);
    Hkdf::<Sha256>::new(Some(b"PoP-key-derivation-v1"), &ikm)
}

/// Compute jitter tag per draft-condrey-rats-pop §5.3:
///   tag-key = HKDF-Expand(PRK, "PoP-jitter-tag-v1", 32)
///   jitter-tag = HMAC-SHA256(tag-key, CBOR-encode(intervals))
pub fn compute_jitter_seal(merkle_root: &[u8], swf_input: &[u8], intervals_cbor: &[u8]) -> Vec<u8> {
    let hk = derive_pop_prk(merkle_root, swf_input);
    let mut tag_key = [0u8; 32];
    hk.expand(b"PoP-jitter-tag-v1", &mut tag_key)
        .expect("32 bytes is valid HKDF-Expand length");

    let mut mac =
        HmacSha256::new_from_slice(&tag_key).expect("32-byte key is valid for HMAC-SHA256");
    tag_key.zeroize();
    mac.update(intervals_cbor);
    mac.finalize().into_bytes().to_vec()
}

/// Compute entangled-binding per draft-condrey-rats-pop §5.3:
///   binding-key = HKDF-Expand(PRK, "PoP-entangled-binding-v1", 32)
///   entangled-binding = HMAC-SHA256(binding-key, prev-hash || content-hash || ...)
pub fn compute_entangled_mac(
    merkle_root: &[u8],
    swf_input: &[u8],
    prev_hash: &[u8],
    content_hash: &[u8],
    jitter_binding_cbor: &[u8],
    physical_state_cbor: &[u8],
) -> Vec<u8> {
    let hk = derive_pop_prk(merkle_root, swf_input);
    let mut binding_key = [0u8; 32];
    hk.expand(b"PoP-entangled-binding-v1", &mut binding_key)
        .expect("32 bytes is valid HKDF-Expand length");

    let mut mac =
        HmacSha256::new_from_slice(&binding_key).expect("32-byte key is valid for HMAC-SHA256");
    binding_key.zeroize();
    mac.update(&(prev_hash.len() as u32).to_be_bytes());
    mac.update(prev_hash);
    mac.update(&(content_hash.len() as u32).to_be_bytes());
    mac.update(content_hash);
    mac.update(&(jitter_binding_cbor.len() as u32).to_be_bytes());
    mac.update(jitter_binding_cbor);
    mac.update(&(physical_state_cbor.len() as u32).to_be_bytes());
    mac.update(physical_state_cbor);
    mac.finalize().into_bytes().to_vec()
}

/// Sign a SecureEvent with a Lamport one-shot signature derived from the
/// device signing key. The Lamport seed is deterministic:
///   seed = HKDF(signing_key, "cpoe-lamport-event-v1", event_hash)
/// so each unique event hash produces a unique one-shot key pair.
pub fn sign_event_lamport(
    signing_key: &ed25519_dalek::SigningKey,
    event: &mut crate::store::SecureEvent,
) -> crate::error::Result<()> {
    let key_bytes = Zeroizing::new(signing_key.to_bytes());
    let hk = Hkdf::<Sha256>::new(Some(b"cpoe-lamport-event-v1"), key_bytes.as_ref());
    let mut seed = Zeroizing::new([0u8; 32]);
    if hk.expand(&event.event_hash, seed.as_mut()).is_err() {
        return Err(crate::error::Error::crypto(
            "HKDF expand failed for Lamport signing",
        ));
    }
    let (privkey, pubkey) = lamport::LamportPrivateKey::from_seed(&seed);
    let sig = privkey.sign(&event.event_hash);
    event.lamport_signature = Some(sig.to_bytes().to_vec());
    event.lamport_pubkey_fingerprint = Some(pubkey.fingerprint().to_vec());
    Ok(())
}

/// Atomically write `data` to `path` via temp-file + fsync + rename.
/// Uses `tempfile` for an unpredictable temp name to prevent symlink attacks.
/// Creates the parent directory if it does not already exist.
pub fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "atomic_write: path must include a parent directory",
            )
        })?;
    // Create parent directory if absent so that NamedTempFile::new_in does not
    // fail with a cryptic "No such file or directory" OS error.
    std::fs::create_dir_all(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    std::io::Write::write_all(&mut tmp, data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error).map(|_| ())
}

/// Owner-only permissions: Unix chmod `mode`, Windows icacls current-user-only.
pub fn restrict_permissions(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(windows)]
    {
        let _ = mode;
        // Set owner-only DACL via Win32 API instead of shelling out to icacls.
        // This is faster, locale-independent, and immune to PATH misconfiguration.
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Security::Authorization::{
            SetNamedSecurityInfoW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            SE_FILE_OBJECT,
        };
        use windows::Win32::Security::{InitializeAcl, ACL, PACL};

        // ACL_REVISION = 2 (Windows SDK constant; not re-exported by the windows crate).
        const ACL_REVISION: u32 = 2;

        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();

        // Build an empty DACL (zero ACEs). An empty DACL explicitly denies all
        // access; the file owner retains the right to modify the DACL via ownership.
        // WARNING: Do NOT use Some(PACL(null_mut())) — a NULL DACL grants everyone
        // full access, the opposite of what is wanted here.
        let mut acl: Box<ACL> = Box::new(
            // SAFETY: ACL is a plain-old-data struct; zero-initializing is valid.
            // InitializeAcl below writes the correct header before first use.
            unsafe { std::mem::zeroed() },
        );
        // SAFETY: `acl` is Box-allocated with correct ACL alignment; size matches.
        if let Err(e) = unsafe {
            InitializeAcl(
                PACL(acl.as_mut() as *mut ACL),
                std::mem::size_of::<ACL>() as u32,
                ACL_REVISION,
            )
        } {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("InitializeAcl failed: {e}"),
            ));
        }

        // SAFETY: `wide` is null-terminated; `acl` was initialized by InitializeAcl above.
        let result = unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,                                  // owner: unchanged
                None,                                  // group: unchanged
                Some(PACL(acl.as_mut() as *mut ACL)), // empty DACL: 0 ACEs = deny all
                None,                                  // SACL: unchanged
            )
        };
        if let Err(e) = result {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("SetNamedSecurityInfoW failed: {e}"),
            ));
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

/// Load the Ed25519 signing key from the data directory with full hardening:
/// symlink-attack protection via `open_validated`/`canonicalize_validated`,
/// Unix permission check (rejects group/other-readable keys), and zeroization.
pub(crate) fn load_signing_key() -> crate::error::Result<ed25519_dalek::SigningKey> {
    let data_dir = crate::utils::get_data_dir()
        .ok_or_else(|| crate::error::Error::identity("Data directory not found"))?;
    let key_path = data_dir.join("signing_key");
    let (canonical, file) = crate::utils::fs::open_validated(&key_path)
        .map_err(|e| crate::error::Error::identity(format!("open signing key: {e}")))?;
    let canonical_data_dir = crate::utils::fs::canonicalize_validated(&data_dir)
        .map_err(|e| crate::error::Error::identity(format!("canonicalize data directory: {e}")))?;
    if !canonical.starts_with(&canonical_data_dir) {
        return Err(crate::error::Error::identity(
            "signing key path resolves outside data directory (possible symlink attack)",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file
            .metadata()
            .map_err(|e| crate::error::Error::identity(format!("stat signing key: {e}")))?;
        let mode = meta.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(crate::error::Error::identity(format!(
                "signing key file has unsafe permissions {:o}; expected owner-only",
                mode
            )));
        }
    }
    let mut buf = Vec::new();
    let mut reader = std::io::BufReader::new(file);
    reader
        .read_to_end(&mut buf)
        .map_err(|e| crate::error::Error::identity(format!("read signing key: {e}")))?;
    let key_data = Zeroizing::new(buf);
    if key_data.len() != 32 {
        return Err(crate::error::Error::identity(format!(
            "signing key file has invalid length {} (expected exactly 32)",
            key_data.len()
        )));
    }
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&key_data[..32]);
    Ok(ed25519_dalek::SigningKey::from_bytes(&secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_seal_deterministic() {
        let root = [0xAA; 32];
        let input = [0x11; 32];
        let intervals = b"test-cbor-data";
        let seal1 = compute_jitter_seal(&root, &input, intervals);
        let seal2 = compute_jitter_seal(&root, &input, intervals);
        assert_eq!(seal1, seal2);
        assert_eq!(seal1.len(), 32);
    }

    #[test]
    fn jitter_seal_varies_with_root() {
        let input = [0x11; 32];
        let intervals = b"test-cbor-data";
        let seal_a = compute_jitter_seal(&[0xAA; 32], &input, intervals);
        let seal_b = compute_jitter_seal(&[0xBB; 32], &input, intervals);
        assert_ne!(seal_a, seal_b);
    }

    #[test]
    fn entangled_mac_deterministic() {
        let root = [0xCC; 32];
        let input = [0x11; 32];
        let prev = [0x01; 32];
        let content = [0x02; 32];
        let jb_cbor = b"jitter-binding";
        let ps_cbor = b"physical-state";
        let mac1 = compute_entangled_mac(&root, &input, &prev, &content, jb_cbor, ps_cbor);
        let mac2 = compute_entangled_mac(&root, &input, &prev, &content, jb_cbor, ps_cbor);
        assert_eq!(mac1, mac2);
        assert_eq!(mac1.len(), 32);
    }

    #[test]
    fn entangled_mac_varies_with_inputs() {
        let root = [0xCC; 32];
        let input = [0x11; 32];
        let prev = [0x01; 32];
        let content = [0x02; 32];
        let mac_a = compute_entangled_mac(&root, &input, &prev, &content, b"jb1", b"ps1");
        let mac_b = compute_entangled_mac(&root, &input, &prev, &content, b"jb2", b"ps1");
        assert_ne!(mac_a, mac_b);
    }

    #[test]
    fn event_hash_deterministic() {
        let device_id = [0x01; 16];
        let timestamp_ns = 1_700_000_000_000_000_000i64;
        let file_path = "/tmp/test.txt";
        let content_hash = [0xAB; 32];
        let file_size = 1024i64;
        let size_delta = 42i32;
        let previous_hash = [0x00; 32];

        let data = EventData {
            device_id,
            timestamp_ns,
            file_path: file_path.to_string(),
            content_hash,
            file_size,
            size_delta,
            previous_hash,
        };

        let h1 = compute_event_hash(&data);
        let h2 = compute_event_hash(&data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn event_hash_changes_with_any_input() {
        let device_id = [0x01; 16];
        let ts = 1_000i64;
        let path = "file.txt";
        let content = [0xAA; 32];
        let prev = [0x00; 32];
        let file_size = 512i64;
        let size_delta = 0i32;

        let data = EventData {
            device_id,
            timestamp_ns: ts,
            file_path: path.to_string(),
            content_hash: content,
            file_size,
            size_delta,
            previous_hash: prev,
        };

        let baseline = compute_event_hash(&data);

        // Different device_id
        let different_device = [0x02; 16];
        let mut d2 = data.clone();
        d2.device_id = different_device;
        assert_ne!(baseline, compute_event_hash(&d2));

        // Different timestamp
        let mut d3 = data.clone();
        d3.timestamp_ns = ts + 1;
        assert_ne!(baseline, compute_event_hash(&d3));

        // Different file path
        let mut d4 = data.clone();
        d4.file_path = "other.txt".to_string();
        assert_ne!(baseline, compute_event_hash(&d4));

        // Different previous hash
        let diff_prev = [0xFF; 32];
        let mut d5 = data.clone();
        d5.previous_hash = diff_prev;
        assert_ne!(baseline, compute_event_hash(&d5));
    }

    #[test]
    fn event_hmac_deterministic() {
        let key = b"test-hmac-key-32-bytes-long!!!!!";
        let device_id = [0x01; 16];
        let ts = 1_700_000_000i64;
        let path = "/doc.txt";
        let content = [0xCC; 32];
        let prev = [0x00; 32];
        let file_size = 0i64;
        let size_delta = 0i32;

        let data = EventData {
            device_id,
            timestamp_ns: ts,
            file_path: path.to_string(),
            content_hash: content,
            file_size,
            size_delta,
            previous_hash: prev,
        };

        let m1 = compute_event_hmac(key, &data);
        let m2 = compute_event_hmac(key, &data);
        assert_eq!(m1, m2);
        assert_eq!(m1.len(), 32);
    }

    #[test]
    fn event_hmac_differs_with_different_keys() {
        let device_id = [0x01; 16];
        let ts = 1_000i64;
        let path = "f.txt";
        let content = [0xAA; 32];
        let prev = [0x00; 32];
        let file_size = 0i64;
        let size_delta = 0i32;

        let data = EventData {
            device_id,
            timestamp_ns: ts,
            file_path: path.to_string(),
            content_hash: content,
            file_size,
            size_delta,
            previous_hash: prev,
        };

        let m1 = compute_event_hmac(b"key-alpha", &data);
        let m2 = compute_event_hmac(b"key-bravo", &data);
        assert_ne!(m1, m2);
    }

    #[test]
    fn event_hmac_differs_from_event_hash() {
        let key = b"some-key";
        let device_id = [0x01; 16];
        let ts = 1_000i64;
        let path = "f.txt";
        let content = [0xAA; 32];
        let prev = [0x00; 32];
        let file_size = 0i64;
        let size_delta = 0i32;

        let data = EventData {
            device_id,
            timestamp_ns: ts,
            file_path: path.to_string(),
            content_hash: content,
            file_size,
            size_delta,
            previous_hash: prev,
        };

        let hash = compute_event_hash(&data);
        let hmac = compute_event_hmac(key, &data);
        assert_ne!(hash.as_slice(), hmac.as_slice());
    }

    #[test]
    fn integrity_hmac_deterministic() {
        let key = b"integrity-key";
        let chain_hash = [0xDD; 32];
        let event_count = 42i64;

        let m1 = compute_integrity_hmac(key, &chain_hash, event_count, 0);
        let m2 = compute_integrity_hmac(key, &chain_hash, event_count, 0);
        assert_eq!(m1, m2);
        assert_eq!(m1.len(), 32);
    }

    #[test]
    fn integrity_hmac_differs_with_key() {
        let chain_hash = [0xDD; 32];
        let m1 = compute_integrity_hmac(b"key-1", &chain_hash, 10, 0);
        let m2 = compute_integrity_hmac(b"key-2", &chain_hash, 10, 0);
        assert_ne!(m1, m2);
    }

    #[test]
    fn integrity_hmac_differs_with_count() {
        let key = b"same-key";
        let chain_hash = [0xDD; 32];
        let m1 = compute_integrity_hmac(key, &chain_hash, 1, 0);
        let m2 = compute_integrity_hmac(key, &chain_hash, 2, 0);
        assert_ne!(m1, m2);
    }

    #[test]
    fn integrity_hmac_differs_with_sequence() {
        let key = b"same-key";
        let chain_hash = [0xDD; 32];
        let m1 = compute_integrity_hmac(key, &chain_hash, 10, 5);
        let m2 = compute_integrity_hmac(key, &chain_hash, 10, 6);
        assert_ne!(m1, m2);
    }

    #[test]
    fn derive_hmac_key_deterministic() {
        let seed = b"my-private-key-seed";
        let k1 = derive_hmac_key(seed);
        let k2 = derive_hmac_key(seed);
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
    }

    #[test]
    fn derive_hmac_key_different_seeds_give_different_keys() {
        let k1 = derive_hmac_key(b"seed-alpha-padded!");
        let k2 = derive_hmac_key(b"seed-bravo-padded!");
        assert_ne!(k1, k2);
    }

    #[test]
    fn derive_hmac_key_for_purpose_deterministic() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let k1 = derive_hmac_key_for_purpose(&sk, "events");
        let k2 = derive_hmac_key_for_purpose(&sk, "events");
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
    }

    #[test]
    fn derive_hmac_key_for_purpose_different_purposes_differ() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let k_events = derive_hmac_key_for_purpose(&sk, "events");
        let k_access = derive_hmac_key_for_purpose(&sk, "access-log");
        assert_ne!(k_events, k_access);
    }

    #[test]
    fn derive_hmac_key_for_purpose_differs_from_legacy() {
        let seed = [0x42; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let legacy = derive_hmac_key(&seed);
        let purpose = derive_hmac_key_for_purpose(&sk, "events");
        assert_ne!(legacy.as_slice(), purpose.as_slice());
    }

    #[test]
    fn hash_file_and_hash_file_with_size_agree() {
        let dir = std::env::temp_dir().join("cpoe_crypto_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_hash.txt");
        let content = b"hello world for hashing";
        std::fs::write(&path, content).unwrap();

        let hash_only = hash_file(&path).unwrap();
        let (hash_with_size, size) = hash_file_with_size(&path).unwrap();

        assert_eq!(hash_only, hash_with_size);
        assert_eq!(size, content.len() as u64);
        assert_eq!(hash_only.len(), 32);

        // Verify against known SHA-256 of the content
        let mut hasher = Sha256::new();
        hasher.update(content);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(hash_only, expected);

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn hash_file_nonexistent_returns_error() {
        let result = hash_file(Path::new("/tmp/cpoe_crypto_nonexistent_file_xyz"));
        assert!(result.is_err());
    }

    #[test]
    fn hash_file_with_size_rejects_oversized() {
        use std::io::{Seek, SeekFrom, Write};
        let dir = std::env::temp_dir().join("cpoe_size_limit_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("oversized_sparse.bin");

        // Create a sparse file whose metadata reports size > MAX_FILE_SIZE.
        // No actual disk blocks are allocated.
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)
                .unwrap();
            f.seek(SeekFrom::Start(crate::MAX_FILE_SIZE + 1)).unwrap();
            f.write_all(&[0u8]).unwrap();
        }

        let result = hash_file_with_size(&path);
        assert!(result.is_err(), "Expected error for file exceeding MAX_FILE_SIZE");
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn atomic_write_rejects_bare_filename() {
        let result = atomic_write(Path::new("bare_filename.txt"), b"data");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn sign_event_lamport_roundtrip() {
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        let mut event =
            crate::store::SecureEvent::new("/test.txt".to_string(), [0x00; 32], 0, None);
        event.event_hash = [0xABu8; 32];

        sign_event_lamport(&signing_key, &mut event).expect("sign_event_lamport failed");
        assert!(event.lamport_signature.is_some());
        assert!(event.lamport_pubkey_fingerprint.is_some());
        assert!(!event.lamport_signature.as_ref().unwrap().is_empty());
    }

    #[test]
    fn sign_event_lamport_deterministic() {
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&[0x11u8; 32]);

        let make_event = || {
            let mut e =
                crate::store::SecureEvent::new("/f.txt".to_string(), [0x00; 32], 0, None);
            e.event_hash = [0xCCu8; 32];
            e
        };

        let mut e1 = make_event();
        let mut e2 = make_event();
        sign_event_lamport(&signing_key, &mut e1).unwrap();
        sign_event_lamport(&signing_key, &mut e2).unwrap();
        assert_eq!(e1.lamport_signature, e2.lamport_signature, "same key+hash must produce same sig");
        assert_eq!(e1.lamport_pubkey_fingerprint, e2.lamport_pubkey_fingerprint);
    }

    #[test]
    fn sign_event_lamport_unique_per_event_hash() {
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&[0x22u8; 32]);

        let make_event = |hash: [u8; 32]| {
            let mut e =
                crate::store::SecureEvent::new("/f.txt".to_string(), [0x00; 32], 0, None);
            e.event_hash = hash;
            e
        };

        let mut e1 = make_event([0xAAu8; 32]);
        let mut e2 = make_event([0xBBu8; 32]);
        sign_event_lamport(&signing_key, &mut e1).unwrap();
        sign_event_lamport(&signing_key, &mut e2).unwrap();
        assert_ne!(e1.lamport_signature, e2.lamport_signature, "different hashes must yield different sigs");
        assert_ne!(e1.lamport_pubkey_fingerprint, e2.lamport_pubkey_fingerprint);
    }
}
