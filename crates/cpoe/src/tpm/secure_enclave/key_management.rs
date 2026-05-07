// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::platform::hardware_uuid;
use super::types::{SecureEnclaveState, SE_ATTESTATION_KEY_TAG, SE_KEY_TAG};
use crate::tpm::TpmError;
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::base::{kCFAllocatorDefault, CFTypeRef};
use core_foundation_sys::error::CFErrorRef;
use security_framework_sys::access_control::{
    kSecAccessControlPrivateKeyUsage, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    SecAccessControlCreateWithFlags,
};
use security_framework_sys::base::{errSecItemNotFound, errSecSuccess, SecKeyRef};
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrApplicationLabel, kSecAttrIsPermanent, kSecAttrKeySizeInBits,
    kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID,
    kSecAttrTokenIDSecureEnclave, kSecClass, kSecClassKey, kSecPrivateKeyAttrs, kSecReturnRef,
};
use security_framework_sys::key::{
    SecKeyCopyExternalRepresentation, SecKeyCopyPublicKey, SecKeyCreateRandomKey,
};
use security_framework_sys::keychain_item::SecItemCopyMatching;
use sha2::{Digest, Sha256};
use std::ptr::null_mut;

pub(super) fn load_or_create_se_key(tag_str: &str) -> Result<(SecKeyRef, Vec<u8>), TpmError> {
    let tag = CFData::from_buffer(tag_str.as_bytes());
    // SAFETY: kSec* constants are static CFStringRef values provided by the Security
    // framework. wrap_under_get_rule increments the refcount so the CFDictionary can
    // hold them safely. The `as CFTypeRef` casts are valid because all kSec* constants
    // are toll-free bridged CFType objects.
    let query = core_foundation::dictionary::CFDictionary::from_CFType_pairs(&[
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFType::wrap_under_get_rule(kSecClassKey as CFTypeRef) },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrApplicationLabel) },
            tag.as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyType) },
            unsafe { CFType::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom as CFTypeRef) },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecReturnRef) },
            CFBoolean::true_value().as_CFType(),
        ),
    ]);

    let mut result: CFTypeRef = null_mut();
    // SAFETY: query is a valid CFDictionary; result is an out-pointer we check before use.
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };

    if status == errSecSuccess && !result.is_null() {
        let key_ref = result as SecKeyRef;
        let public_key = match extract_public_key(key_ref) {
            Ok(pk) => pk,
            Err(e) => {
                // SAFETY: key_ref is a non-null SecKeyRef we own (+1 from SecItemCopyMatching); release to avoid leak.
                unsafe { core_foundation_sys::base::CFRelease(key_ref as CFTypeRef) };
                return Err(e);
            }
        };
        return Ok((key_ref, public_key));
    }
    if status != errSecItemNotFound {
        return Err(TpmError::KeyGeneration(format!(
            "Keychain query failed with status {status} for tag {tag_str}"
        )));
    }

    // SAFETY: kCFAllocatorDefault and kSecAttr* are valid static constants.
    // access_error is an out-pointer; we check and release it below.
    let mut access_error: CFErrorRef = null_mut();
    let access = unsafe {
        SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly as CFTypeRef,
            kSecAccessControlPrivateKeyUsage,
            &mut access_error,
        )
    };

    // SAFETY: kSec* constants are static CFStringRef values; wrap_under_get_rule
    // retains them for the dictionary's lifetime.
    let mut private_pairs: Vec<(CFString, CFType)> = Vec::new();
    private_pairs.push((
        unsafe { CFString::wrap_under_get_rule(kSecAttrIsPermanent) },
        CFBoolean::true_value().as_CFType(),
    ));
    private_pairs.push((
        unsafe { CFString::wrap_under_get_rule(kSecAttrApplicationLabel) },
        tag.as_CFType(),
    ));
    if access.is_null() {
        if !access_error.is_null() {
            // SAFETY: access_error is a non-null CFErrorRef we own; release to avoid leak.
            unsafe { core_foundation_sys::base::CFRelease(access_error as CFTypeRef) };
        }
        return Err(TpmError::KeyGeneration(
            "SecAccessControlCreateWithFlags returned null".into(),
        ));
    }
    // On success, error should be null per Apple docs; release defensively if not.
    if !access_error.is_null() {
        unsafe { core_foundation_sys::base::CFRelease(access_error as CFTypeRef) };
    }

    // SAFETY: access is non-null (checked above). wrap_under_create_rule takes
    // ownership, so CFDictionary will release it when dropped.
    private_pairs.push((
        unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) },
        unsafe { CFType::wrap_under_create_rule(access as CFTypeRef) },
    ));
    let private_attrs =
        core_foundation::dictionary::CFDictionary::from_CFType_pairs(&private_pairs);

    let key_size = 256i32;
    let key_size_cf = CFNumber::from(key_size);

    // SAFETY: Same pattern as query dict above; all kSec* are static CFStringRef.
    let key_attrs = core_foundation::dictionary::CFDictionary::from_CFType_pairs(&[
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeyType) },
            unsafe { CFType::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom as CFTypeRef) },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrKeySizeInBits) },
            key_size_cf.as_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrTokenID) },
            unsafe { CFType::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave as CFTypeRef) },
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecPrivateKeyAttrs) },
            private_attrs.as_CFType(),
        ),
    ]);

    let mut error: CFErrorRef = null_mut();
    // SAFETY: key_attrs is a valid CFDictionary; error is an out-pointer we release below.
    let key_ref = unsafe { SecKeyCreateRandomKey(key_attrs.as_concrete_TypeRef(), &mut error) };

    if key_ref.is_null() {
        if !error.is_null() {
            // SAFETY: error is a non-null CFErrorRef that we own; release to avoid leak.
            unsafe { core_foundation_sys::base::CFRelease(error as CFTypeRef) };
        }
        return Err(TpmError::KeyGeneration(format!(
            "Secure Enclave key generation failed for tag {tag_str}"
        )));
    }

    // On success, error should be null per Apple docs; release defensively if not.
    if !error.is_null() {
        unsafe { core_foundation_sys::base::CFRelease(error as CFTypeRef) };
    }

    let public_key = match extract_public_key(key_ref) {
        Ok(pk) => pk,
        Err(e) => {
            // SAFETY: key_ref is a non-null SecKeyRef we own (+1 from SecKeyCreateRandomKey); release to avoid leak.
            unsafe { core_foundation_sys::base::CFRelease(key_ref as CFTypeRef) };
            return Err(e);
        }
    };
    Ok((key_ref, public_key))
}

pub(super) fn load_or_create_attestation_key(
    state: &mut SecureEnclaveState,
) -> Result<(), TpmError> {
    let (key_ref, public_key) = load_or_create_se_key(SE_ATTESTATION_KEY_TAG)?;
    state.attestation_key_ref = Some(key_ref);
    state.attestation_public_key = Some(public_key);
    Ok(())
}

pub(super) fn load_device_id() -> Result<String, TpmError> {
    if let Some(uuid) = hardware_uuid() {
        let digest = Sha256::digest(uuid.as_bytes());
        return Ok(format!("se-{}", crate::utils::short_hex_id(&digest)));
    }
    let host = hostname::get().map_err(|e| {
        log::warn!("load_device_id: hostname lookup failed: {e}");
        TpmError::NotAvailable
    })?;
    let digest = Sha256::digest(format!("cpoe-fallback-{}", host.to_string_lossy()).as_bytes());
    Ok(format!("se-{}", crate::utils::short_hex_id(&digest)))
}

pub(super) fn load_or_create_key(state: &mut SecureEnclaveState) -> Result<(), TpmError> {
    let (key_ref, public_key) = load_or_create_se_key(SE_KEY_TAG)?;
    state.key_ref = key_ref;
    state.public_key = public_key;
    Ok(())
}

pub(super) fn extract_public_key(key_ref: SecKeyRef) -> Result<Vec<u8>, TpmError> {
    // SAFETY: key_ref is a valid SecKeyRef obtained from SecItemCopyMatching or
    // SecKeyCreateRandomKey. SecKeyCopyPublicKey returns a new +1 ref we must release.
    let public_key = unsafe { SecKeyCopyPublicKey(key_ref) };
    if public_key.is_null() {
        return Err(TpmError::KeyExport("SecKeyCopyPublicKey returned null".into()));
    }
    let mut error: CFErrorRef = null_mut();
    // SAFETY: public_key is non-null (checked above); error is an out-pointer.
    let data_ref = unsafe { SecKeyCopyExternalRepresentation(public_key, &mut error) };
    if data_ref.is_null() {
        // SAFETY: error is a +1 CFErrorRef we own from SecKeyCopyExternalRepresentation; release if non-null.
        if !error.is_null() {
            unsafe { core_foundation_sys::base::CFRelease(error as CFTypeRef) };
        }
        // SAFETY: public_key is a non-null CF object we own; release to avoid leak.
        unsafe { core_foundation_sys::base::CFRelease(public_key as *mut std::ffi::c_void) };
        return Err(TpmError::KeyExport("SecKeyCopyExternalRepresentation returned null".into()));
    }
    // SAFETY: data_ref is non-null (checked above); wrap_under_create_rule takes ownership.
    let data = unsafe { CFData::wrap_under_create_rule(data_ref) };
    let result = data.bytes().to_vec();
    // On success, error should be null per Apple docs; release defensively if not.
    if !error.is_null() {
        unsafe { core_foundation_sys::base::CFRelease(error as CFTypeRef) };
    }
    // SAFETY: public_key is a non-null CF object we own; release after extracting bytes.
    unsafe { core_foundation_sys::base::CFRelease(public_key as *mut std::ffi::c_void) };
    Ok(result)
}
