// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use std::sync::OnceLock;
use std::time::Duration;

use crate::ffi::helpers::load_signing_key;
use crate::ffi::types::{catch_ffi_panic, try_ffi, FfiResult};
use crate::identity::did_webvh::WebVHIdentity;

const FFI_TIMEOUT_SECS: u64 = 30;

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Runtime::new().unwrap_or_else(|e| {
            log::error!("Multi-threaded tokio runtime failed: {e}; falling back to current-thread");
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("current-thread tokio runtime")
        })
    })
}

/// Create a new did:webvh identity bound to the given address.
///
/// Loads the signing key from disk, derives a did:webvh key via HKDF,
/// creates the DID document, and persists the state. Returns the DID
/// string in `message` on success.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_create_webvh_identity(address: String) -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!("ffi_create_webvh_identity: address={}", address);
    if address.len() > 2048 {
        return FfiResult::err("Address too long");
    }
    let signing_key = match load_signing_key() {
        Ok(k) => k,
        Err(e) => {
            log::error!("ffi_create_webvh_identity: load signing key: {e}");
            return FfiResult::err("Failed to load signing key");
        }
    };

    let result = runtime().block_on(async {
        tokio::time::timeout(
            Duration::from_secs(FFI_TIMEOUT_SECS),
            WebVHIdentity::create(&signing_key, &address),
        )
        .await
    });
    drop(signing_key);

    let identity = match result {
        Ok(Ok(id)) => id,
        Ok(Err(e)) => {
            log::error!("ffi_create_webvh_identity: create: {e}");
            return FfiResult::err("Failed to create did:webvh identity");
        }
        Err(_) => return FfiResult::err("Identity creation timed out"),
    };

    if let Err(e) = identity.save() {
        log::error!("ffi_create_webvh_identity: save: {e}");
        return FfiResult::err("Failed to save identity state");
    }

    FfiResult::ok(identity.did().to_string())
    })
}

/// Return the current did:webvh DID string.
///
/// Loads the persisted did:webvh identity from disk. Returns success=false
/// if no did:webvh identity has been created.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_webvh_did() -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!("ffi_get_webvh_did");
    match WebVHIdentity::load() {
        Ok(identity) => FfiResult::ok(identity.did().to_string()),
        Err(e) => {
            log::debug!("ffi_get_webvh_did: {e}");
            FfiResult::err("No did:webvh identity configured")
        }
    }
    })
}

/// Return the active author DID, preferring did:webvh over did:key.
///
/// Calls `load_active_did()` which tries did:webvh first, then falls
/// back to did:key derived from the signing key on disk.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_get_active_did() -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!("ffi_get_active_did");
    match crate::identity::did_webvh::load_active_did() {
        Ok(did) => FfiResult::ok(did),
        Err(e) => {
            log::error!("ffi_get_active_did: {e}");
            FfiResult::err("Failed to resolve active DID")
        }
    }
    })
}

/// Deactivate the did:webvh identity.
///
/// Loads the signing key and persisted identity, calls deactivate on the
/// did:webvh state, and saves the updated (deactivated) state to disk.
#[cfg_attr(feature = "ffi", uniffi::export)]
pub fn ffi_deactivate_webvh_identity() -> FfiResult {
    catch_ffi_panic!(FfiResult::err("engine internal error"), {
    log::debug!("ffi_deactivate_webvh_identity");
    let signing_key = match load_signing_key() {
        Ok(k) => k,
        Err(e) => {
            log::error!("ffi_deactivate_webvh_identity: load signing key: {e}");
            return FfiResult::err("Failed to load signing key");
        }
    };

    let mut identity = match WebVHIdentity::load() {
        Ok(id) => id,
        Err(e) => {
            log::error!("ffi_deactivate_webvh_identity: load identity: {e}");
            return FfiResult::err("No did:webvh identity to deactivate");
        }
    };

    let result = runtime().block_on(async {
        tokio::time::timeout(
            Duration::from_secs(FFI_TIMEOUT_SECS),
            identity.deactivate(&signing_key),
        )
        .await
    });
    drop(signing_key);

    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            log::error!("ffi_deactivate_webvh_identity: deactivate: {e}");
            return FfiResult::err("Failed to deactivate identity");
        }
        Err(_) => return FfiResult::err("Identity deactivation timed out"),
    }

    if let Err(e) = identity.save() {
        log::error!("ffi_deactivate_webvh_identity: save: {e}");
        return FfiResult::err("Failed to save deactivated state");
    }

    FfiResult::ok("did:webvh identity deactivated".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FFI get_webvh_did returns failure when no identity exists.
    #[test]
    fn get_webvh_did_no_identity() {
        let result = ffi_get_webvh_did();
        assert!(!result.success);
        assert!(result.error_message.is_some());
        let msg = result.error_message.unwrap();
        assert!(
            !msg.contains('/') && !msg.contains("No such file"),
            "error must not leak filesystem details, got: {msg}"
        );
    }

    /// FFI get_active_did returns a DID or a sanitized error.
    #[test]
    fn get_active_did_sanitized_error() {
        let result = ffi_get_active_did();
        if !result.success {
            let msg = result.error_message.unwrap_or_default();
            assert!(
                !msg.contains('/') && !msg.contains("No such file"),
                "error must not leak filesystem details, got: {msg}"
            );
        }
    }

    /// FFI create_webvh_identity rejects empty address via validation.
    #[test]
    fn create_rejects_empty_address() {
        let result = ffi_create_webvh_identity("".to_string());
        assert!(!result.success);
    }

    /// FFI deactivate returns failure when no identity exists.
    #[test]
    fn deactivate_no_identity() {
        let result = ffi_deactivate_webvh_identity();
        assert!(!result.success);
        let msg = result.error_message.unwrap_or_default();
        assert!(
            !msg.contains('/') && !msg.contains("No such file"),
            "error must not leak filesystem details, got: {msg}"
        );
    }

    /// Error messages at FFI boundary must not contain internal details.
    #[test]
    fn error_result_is_generic() {
        let r = FfiResult::err("test message");
        assert!(!r.success);
        assert_eq!(r.error_message.as_deref(), Some("test message"));
        assert!(r.message.is_none());
    }

    /// Ok result contains the DID in message field.
    #[test]
    fn ok_result_carries_message() {
        let r = FfiResult::ok("did:webvh:example.com:abc".to_string());
        assert!(r.success);
        assert_eq!(r.message.as_deref(), Some("did:webvh:example.com:abc"));
        assert!(r.error_message.is_none());
    }
}
