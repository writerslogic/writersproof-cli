// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("{0}")]
    General(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl PlatformError {
    pub fn general(m: impl Into<String>) -> Self {
        PlatformError::General(m.into())
    }
}

pub type PlatformResult<T> = std::result::Result<T, PlatformError>;
