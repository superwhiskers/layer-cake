// SPDX-License-Identifier: AGPL-3.0-only

//! Error handling and definitions used across bubblebox.

/// Enumeration over errors surfaced by bubblebox.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum Error {
    /// Guest path handling error.
    GuestPath(GuestPath),
}

impl From<GuestPath> for Error {
    fn from(error: GuestPath) -> Self {
        Self::GuestPath(error)
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
}
