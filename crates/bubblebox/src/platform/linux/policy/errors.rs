// SPDX-License-Identifier: AGPL-3.0-only

//! Error types surfaced from policy handling code.

use meowix::errors::{CStrBufferTooSmall, SyscallError};

/// Enumeration over errors related to the policy.
#[non_exhaustive]
#[derive(Debug)]
pub enum Policy {
    /// A syscall failed.
    Syscall(SyscallError),

    /// File did not turn out to be a file.
    NotAFile,

    /// Directory did not turn out to be a directory.
    NotADirectory,

    /// File descriptor policy was invalid.
    InvalidFdPolicy,

    /// Mount policy was invalid.
    InvalidMountPolicy,

    /// Buffer used for C string conversion was too small.
    CStrBufferTooSmall,

    /// A string being converted to a C string contained a null byte.
    FromBytesWithNulError(std::ffi::FromBytesWithNulError),
}

impl From<SyscallError> for Policy {
    fn from(error: SyscallError) -> Self {
        Self::Syscall(error)
    }
}

impl From<CStrBufferTooSmall> for Policy {
    fn from(_: CStrBufferTooSmall) -> Self {
        Self::CStrBufferTooSmall
    }
}

impl From<std::ffi::FromBytesWithNulError> for Policy {
    fn from(error: std::ffi::FromBytesWithNulError) -> Self {
        Self::FromBytesWithNulError(error)
    }
}
