// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use thiserror::Error;

#[derive(Debug, Error)]
pub enum FingerprintError {
    #[error("{0}")]
    General(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl FingerprintError {
    pub fn general(m: impl Into<String>) -> Self {
        FingerprintError::General(m.into())
    }
}

pub type FingerprintResult<T> = std::result::Result<T, FingerprintError>;
