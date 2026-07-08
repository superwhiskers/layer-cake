// SPDX-License-Identifier: AGPL-3.0-only

//! Error handling and definitions used across bubblebox.

use crate::platform::errors::Error as PlatformError;

/// Enumeration over errors surfaced by bubblebox.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// Guest path handling error.
    GuestPath(GuestPath),

    /// Platform error.
    Platform(PlatformError),
}

impl From<GuestPath> for Error {
    fn from(error: GuestPath) -> Self {
        Self::GuestPath(error)
    }
}

impl From<PlatformError> for Error {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

/// Enumeration over errors involved in guest path handling.
#[non_exhaustive]
#[derive(Copy, Clone, Debug)]
pub enum GuestPath {
    /// Path was not absolute.
    PathNotAbsolute,

    /// Path contains parent.
    PathContainsParent,

    /// Guest path has a path prefix.
    GuestPathHasPrefix,

    /// Guest path lacked a parent directory.
    NoParentDirectory,

    /// Guest path lacked a file name.
    NoFileName,

    /// Guest path was invalid for the target platform.
    //TODO: wrap the internal error, make it castable
    Invalid,
}
