// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid public key: {0}")]
    InvalidPublicKey(#[from] ed25519_dalek::SignatureError),

    #[error("{0}")]
    Validation(String),

    #[error("database locked: {0}")]
    DatabaseLocked(String),

    #[error("integrity: {0}")]
    Integrity(String),
}

impl StoreError {
    pub fn validation(m: impl Into<String>) -> Self {
        StoreError::Validation(m.into())
    }
    pub fn integrity(m: impl Into<String>) -> Self {
        StoreError::Integrity(m.into())
    }
    pub fn database_locked(m: impl Into<String>) -> Self {
        StoreError::DatabaseLocked(m.into())
    }
}

pub type StoreResult<T> = std::result::Result<T, StoreError>;
