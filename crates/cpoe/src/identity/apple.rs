// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use anyhow::{anyhow, Result};
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
use security_framework::key::{Algorithm, SecKey};

#[derive(Debug)]
/// Handle to an ECDSA signing key stored in the macOS Secure Enclave.
pub struct SecureEnclaveIdentity {
    /// Reference to the Secure Enclave key.
    pub key: SecKey,
}

impl SecureEnclaveIdentity {
    /// Load a Secure Enclave key by its Keychain label.
    pub fn load(label: &str) -> Result<Self> {
        log::debug!("SecureEnclaveIdentity::load: label={}", label);
        let mut search = ItemSearchOptions::default();
        search.class(ItemClass::key());
        search.label(label);
        search.limit(Limit::All);

        let results = search
            .search()
            .map_err(|_| anyhow!("Key not found in Secure Enclave"))?;

        for item in results {
            if let SearchResult::Ref(Reference::Key(k)) = item {
                return Ok(Self { key: k });
            }
        }

        Err(anyhow!("No valid key reference found in Secure Enclave"))
    }

    /// Sign a 32-byte hash using ECDSA via the Secure Enclave.
    pub fn sign(&self, hash: &[u8; 32]) -> Result<Vec<u8>> {
        log::debug!("SecureEnclaveIdentity::sign: hash_len={}", hash.len());
        let signature = self
            .key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, hash)
            .map_err(|e| anyhow!("Hardware signing failed: {:?}", e))?;

        Ok(signature)
    }
}
