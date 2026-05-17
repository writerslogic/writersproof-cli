// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

#[cfg(target_os = "macos")]
pub mod apple;
pub mod bridge;
pub mod did_configuration;
pub mod did_document;
pub mod mnemonic;
pub mod openid4vc;
pub mod orcid;
pub mod presentation_exchange;
pub mod secure_storage;

/// WritersProof profile DID for the currently signed-in user.
/// Set via `ffi_set_profile_did` on login; cleared on logout.
pub static PROFILE_DID: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

#[cfg(feature = "did-webvh")]
pub mod did_webvh;

pub use did_document::did_key_from_public;
pub use mnemonic::MnemonicHandler;
pub use secure_storage::{InMemoryBackend, KeychainBackend, SecureStorage};
