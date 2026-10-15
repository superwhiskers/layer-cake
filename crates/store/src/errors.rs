// SPDX-License-Identifier: AGPL-3.0-only

//! Error definitions for the store library component.

use std::{error, fmt};

/// Enumeration over errors that may occur while working with the store implementation.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// Backend error.
    //NOTE: i wouldn't normally prefer this but because there is not a single
    //      backend per platform there's not a sane way to allow consumers to
    //      use "just this one type" unless they only ever use a single backend
    Backend(Box<dyn error::Error + Send + Sync>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(e) => write!(f, "backend: {e}"),
        }
    }
}

impl error::Error for Error {}

#[cfg(target_os = "linux")]
impl From<crate::linux::BackendError> for Error {
    fn from(error: crate::linux::BackendError) -> Self {
        Self::Backend(error.into())
    }
}
