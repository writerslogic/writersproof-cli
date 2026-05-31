// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use std::path::Path;
use std::time::Duration;

use crate::checkpoint;

use super::error::KeyHierarchyError;
use super::identity::derive_master_identity;
use super::session::{start_session, start_session_with_key};
use super::types::{MasterIdentity, PufProvider, Session};

pub struct SessionManager {
    pub session: Session,
    pub identity: MasterIdentity,
    /// Retained to keep PUF provider alive for session recovery
    _puf: Box<dyn PufProvider>,
    /// Retained for document re-loading during session recovery
    _document_path: String,
}

impl SessionManager {
    /// Create a new session manager for the given document.
    ///
    /// Callers may pre-compute `doc_hash` externally to avoid double-hashing
    /// if the file content is already known; use `new_with_hash` in that case.
    pub fn new(
        puf: Box<dyn PufProvider>,
        document_path: impl Into<String>,
    ) -> Result<Self, KeyHierarchyError> {
        let identity = derive_master_identity(puf.as_ref())?;
        let document_path = document_path.into();
        let document_path = std::fs::canonicalize(&document_path)
            .unwrap_or_else(|e| {
                log::debug!("canonicalize failed for {}: {e}", document_path);
                std::path::PathBuf::from(&document_path)
            })
            .to_string_lossy()
            .to_string();
        let doc_hash = crate::crypto::hash_file(Path::new(&document_path))?;

        let session = start_session(puf.as_ref(), doc_hash)?;

        Ok(Self {
            session,
            identity,
            _puf: puf,
            _document_path: document_path,
        })
    }

    /// Create a session manager using a `SealedIdentityStore` for TPM-protected key material.
    ///
    /// The master signing key is obtained via `sealed.unseal_master_key()` (TPM-protected)
    /// rather than `derive_master_private_key(puf)` (in-memory derivation).
    pub fn new_with_sealed_store(
        sealed: &crate::sealed_identity::SealedIdentityStore,
        puf: Box<dyn PufProvider>,
        document_path: impl Into<String>,
    ) -> Result<Self, KeyHierarchyError> {
        let identity = sealed
            .public_identity()
            .map_err(|e| KeyHierarchyError::Crypto(format!("sealed identity error: {}", e)))?;

        let document_path = document_path.into();
        let doc_hash = crate::crypto::hash_file(Path::new(&document_path))?;

        // SigningKey implements Zeroize on Drop — it is automatically zeroized
        // when this binding goes out of scope at the end of this function.
        let master_key = sealed
            .unseal_master_key()
            .map_err(|e| KeyHierarchyError::Crypto(format!("unseal master key: {}", e)))?;

        let session = start_session_with_key(&master_key, doc_hash)?;

        Ok(Self {
            session,
            identity,
            _puf: puf,
            _document_path: document_path,
        })
    }

    pub fn sign_checkpoint(
        &mut self,
        checkpoint: &mut checkpoint::Checkpoint,
    ) -> Result<(), KeyHierarchyError> {
        let sig = self.session.sign_checkpoint(checkpoint.hash)?;
        checkpoint.signature = Some(sig.signature.to_vec());
        Ok(())
    }

}

#[derive(Debug)]
pub struct ChainSigner {
    pub chain: checkpoint::Chain,
    pub manager: SessionManager,
}

impl ChainSigner {
    pub fn new(
        chain: checkpoint::Chain,
        puf: Box<dyn PufProvider>,
    ) -> Result<Self, KeyHierarchyError> {
        let manager = SessionManager::new(puf, chain.metadata.document_path.clone())?;
        Ok(Self { chain, manager })
    }

    /// Sign the last checkpoint in the chain, returning a clone.
    fn sign_last_checkpoint(&mut self) -> Result<checkpoint::Checkpoint, KeyHierarchyError> {
        let cp = self
            .chain
            .checkpoints
            .last_mut()
            .ok_or_else(|| KeyHierarchyError::Crypto("no checkpoint after commit".into()))?;
        self.manager.sign_checkpoint(cp)?;
        Ok(cp.clone())
    }

    pub fn commit_and_sign(
        &mut self,
        message: Option<String>,
    ) -> Result<checkpoint::Checkpoint, KeyHierarchyError> {
        self.chain
            .commit(message)
            .map_err(|e| KeyHierarchyError::Crypto(format!("{e:#}")))?;
        self.sign_last_checkpoint()
    }

    pub fn commit_and_sign_with_duration(
        &mut self,
        message: Option<String>,
        vdf_duration: Duration,
    ) -> Result<checkpoint::Checkpoint, KeyHierarchyError> {
        self.chain
            .commit_with_vdf_duration(message, vdf_duration)
            .map_err(|e| KeyHierarchyError::Crypto(format!("{e:#}")))?;
        self.sign_last_checkpoint()
    }
}

impl std::fmt::Debug for SessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionManager").finish_non_exhaustive()
    }
}
