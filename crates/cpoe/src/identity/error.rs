// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("{0}")]
    General(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl IdentityError {
    pub fn general(m: impl Into<String>) -> Self {
        IdentityError::General(m.into())
    }
}

pub type IdentityResult<T> = std::result::Result<T, IdentityError>;
