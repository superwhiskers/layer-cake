// SPDX-License-Identifier: AGPL-3.0-only

//! Sandbox path abstraction.

//TODO: add a reference type for this, like we have in the linux backend. then
//      edit everything else to take it
//TODO: impl borrow for this?

use std::path::{Path, PathBuf};

use crate::{errors::Error, platform::paths::GuestInner};

/// Path residing within the sandbox.
///
/// A guest path contains a normalized, absolute path residing within a
/// sandbox. Guest paths are never valid outside the sandbox they belong to.
/// Guest paths are not valid on the host. Guest paths must not contain
/// characters invalid for a path on the host system. Guest paths must not
/// contain a Windows path prefix.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Guest {
    pub(crate) inner: GuestInner,
}

impl Guest {
    /// Constructs a new guest path from the given [`Path`].
    ///
    /// # Notes
    ///
    /// Currently this does not attempt to resolve potential symlinks within
    /// the sandbox. This will be handled in the future.
    ///
    /// # Errors
    ///
    /// This method errors if the provided path fails the validation step.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, Error> {
        Ok(Self {
            inner: GuestInner::new(path)?,
        })
    }

    /// Indicates if the path starts with the specified path.
    pub fn starts_with(&self, other: &Self) -> bool {
        self.inner.starts_with(&other.inner)
    }
}

impl TryFrom<&Path> for Guest {
    type Error = Error;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        Self::new(path)
    }
}

impl TryFrom<PathBuf> for Guest {
    type Error = Error;

    fn try_from(path: PathBuf) -> Result<Self, Self::Error> {
        Self::new(path)
    }
}

impl TryFrom<&str> for Guest {
    type Error = Error;

    fn try_from(path: &str) -> Result<Self, Self::Error> {
        Self::new(PathBuf::from(path))
    }
}
