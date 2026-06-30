// SPDX-License-Identifier: AGPL-3.0-only

//! Sandbox path abstraction.

//TODO: add `TryInto<PathBuf>`? --- odd form, but we cannot implement
//      `TryFrom` on `PathBuf`

use std::path::{Component, Path, PathBuf};

use crate::errors::Error;

/// Path residing within the sandbox.
///
/// A guest path contains a normalized, absolute path residing within a
/// sandbox. Guest paths are never valid outside the sandbox they belong to.
/// Guest paths are not valid on the host. Guest paths must not contain
/// characters invalid for a path on the host system. Guest paths must not
/// contain a Windows path prefix.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Guest(PathBuf);

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
        let path = path.as_ref();

        if !path.is_absolute() {
            return Err(Error::PathNotAbsolute);
        }

        let mut normalized = PathBuf::from("/");

        for component in path.components() {
            match component {
                //NOTE: the former is expected and the latter is normalized
                //      away or excluded by checking that the path is not
                //      relative earlier
                Component::RootDir | Component::CurDir => {}

                Component::Normal(c) => normalized.push(c),
                Component::ParentDir => {
                    return Err(Error::PathContainsParent);
                }
                Component::Prefix(_) => {
                    return Err(Error::GuestPathHasPrefix);
                }
            }
        }

        Ok(Self(normalized))
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

impl AsRef<Path> for Guest {
    fn as_ref(&self) -> &Path {
        self.0.as_path()
    }
}
