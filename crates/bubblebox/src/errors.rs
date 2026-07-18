// SPDX-License-Identifier: AGPL-3.0-only

//! Error handling and definitions used across bubblebox.

use std::{error, fmt};

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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GuestPath(e) => write!(f, "guest path: {e}"),
            Self::Platform(e) => write!(f, "platform: {e}"),
        }
    }
}

impl error::Error for Error {}

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

    /// Path references parent.
    PathContainsParent,

    /// Guest path has a path prefix.
    PathContainsPrefix,

    /// Guest path lacked a parent directory.
    NoParentDirectory,

    /// Guest path lacked a file name.
    NoFileName,

    /// Guest path was invalid for the target platform.
    //TODO: wrap the internal error, make it castable
    Invalid,
}

impl fmt::Display for GuestPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PathNotAbsolute => "the path provided was not absolute",
            Self::PathContainsParent => {
                "the path provided references the parent directory within it"
            }
            Self::PathContainsPrefix => "the path provided contains a prefix",
            Self::NoParentDirectory => {
                "the path provided lacks a parent directory"
            }
            Self::NoFileName => "the path provided lacks a file name",
            Self::Invalid => "the path was invalid for the target platform",
        })
    }
}
