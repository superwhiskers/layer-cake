// SPDX-License-Identifier: AGPL-3.0-only

//! Error definitions for the Linux directory backend.

use meowix::errors::{CStrBufferTooSmall, PartialTransfer, SyscallError};
use std::{error, ffi, fmt, io, num::ParseIntError};

/// Enumeration over errors that may occur while working with the Linux store
/// backend.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// File descriptor passed to `DirectoryBackend::new` did not reference a
    /// directory.
    NotADirectory,

    /// Syscall error.
    Syscall(SyscallError),

    /// Buffer used for C string conversion was too small.
    CStrBufferTooSmall,

    /// String being converted to a C string contained a null byte.
    FromBytesWithNul(ffi::FromBytesWithNulError),

    /// String being converted to an integer was invalid.
    ParseIntError(ParseIntError),

    /// Transfer that should have been fixed size was incomplete.
    PartialTransfer(PartialTransfer),

    /// I/O error.
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotADirectory => {
                f.write_str("specified directory was not a directory")
            }
            Self::Syscall(e) => write!(f, "syscall error: {e}"),
            Self::CStrBufferTooSmall => f.write_str(
                "a buffer used for C string conversion was too small",
            ),
            Self::FromBytesWithNul(e) => {
                write!(f, "C string conversion error: {e}")
            }
            Self::ParseIntError(e) => {
                write!(f, "invalid integer: {e}")
            }
            Self::PartialTransfer(e) => {
                write!(
                    f,
                    "transfer that should have been fixed size was incomplete: {e}"
                )
            }
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl error::Error for Error {}

impl From<SyscallError> for Error {
    fn from(error: SyscallError) -> Self {
        Self::Syscall(error)
    }
}

impl From<CStrBufferTooSmall> for Error {
    fn from(_: CStrBufferTooSmall) -> Self {
        Self::CStrBufferTooSmall
    }
}

impl From<ffi::FromBytesWithNulError> for Error {
    fn from(error: ffi::FromBytesWithNulError) -> Self {
        Self::FromBytesWithNul(error)
    }
}

impl From<ParseIntError> for Error {
    fn from(error: ParseIntError) -> Self {
        Self::ParseIntError(error)
    }
}

impl From<PartialTransfer> for Error {
    fn from(error: PartialTransfer) -> Self {
        Self::PartialTransfer(error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
