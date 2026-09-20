// SPDX-License-Identifier: AGPL-3.0-only

//! Specialized error type for Linux backend procedures.

use meowix::errors::{CStrBufferTooSmall, SyscallError};
use std::{error, fmt};

use super::{
    policy::errors::Policy,
    spawn::errors::{PostSpawnGuest, PostSpawnHost, PreSpawn},
};

/// Enumeration over errors surfaced by the bubblebox Linux backend.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// Policy error.
    Policy(Policy),

    /// Pre-spawn error.
    PreSpawn(PreSpawn),

    /// Post-spawn error from the host.
    PostSpawnHost(PostSpawnHost),

    /// Post-spawn error from the guest.
    PostSpawnGuest(PostSpawnGuest),

    /// Command or child interface error.
    Command(Command),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(e) => write!(f, "policy: {e}"),
            Self::PreSpawn(e) => write!(f, "pre-spawn: {e}"),
            Self::PostSpawnHost(e) => write!(f, "post-spawn (host): {e}"),
            Self::PostSpawnGuest(e) => write!(f, "post-spawn (guest): {e}"),
            Self::Command(e) => write!(f, "command: {e}"),
        }
    }
}

impl error::Error for Error {}

impl From<Policy> for Error {
    fn from(error: Policy) -> Self {
        Self::Policy(error)
    }
}

impl From<PreSpawn> for Error {
    fn from(error: PreSpawn) -> Self {
        Self::PreSpawn(error)
    }
}

impl From<PostSpawnHost> for Error {
    fn from(error: PostSpawnHost) -> Self {
        Self::PostSpawnHost(error)
    }
}

impl From<PostSpawnGuest> for Error {
    fn from(error: PostSpawnGuest) -> Self {
        Self::PostSpawnGuest(error)
    }
}

impl From<Command> for Error {
    fn from(error: Command) -> Self {
        Self::Command(error)
    }
}

/// Trait to simplify tagging errors with a phase.
pub(crate) trait Tag {
    /// Tag this error with an error and return the wrapper [`Error`].
    fn tag_with<E>(self) -> Error
    where
        Self: Into<E>,
        E: Into<Error>,
    {
        <Self as Into<E>>::into(self).into()
    }
}

impl<T> Tag for T {}

/// Extension trait for [`Result<T, SyscallError>`] that makes tagging errors
/// simpler.
pub(crate) trait ResultSyscallExt<T>:
    Sized + Into<Result<T, SyscallError>>
{
    /// Wraps the syscall error with an annotation about which phase it was
    /// called in.
    fn wrap_error<I>(self) -> Result<T, Error>
    where
        SyscallError: Into<I>,
        I: Into<Error>,
    {
        self.into().map_err(Tag::tag_with::<I>)
    }
}

impl<T> ResultSyscallExt<T> for Result<T, SyscallError> {}

/// Enumeration over errors that occur in the command or child interface.
#[non_exhaustive]
#[derive(Debug)]
pub enum Command {
    /// Syscall error.
    Syscall(SyscallError),

    /// Kernel did not return requested information about the process.
    MissingInformation,

    /// Environment variable key contained an equals (`=`) character.
    InvalidEnvironmentVariable,

    /// C string buffer was too small.
    CStrBufferTooSmall,

    /// The type being converted to a C string was invalid.
    NulError(std::ffi::NulError),
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syscall(e) => write!(f, "syscall error: {e}"),
            Self::MissingInformation => f.write_str(
                "kernel did not return requested process information",
            ),
            Self::InvalidEnvironmentVariable => f.write_str(
                "an environment variable key contained the equals character",
            ),
            Self::CStrBufferTooSmall => f.write_str(
                "a buffer used for C string conversion was too small",
            ),
            Self::NulError(e) => {
                write!(f, "C string conversion error: {e}")
            }
        }
    }
}

impl error::Error for Command {}

impl From<SyscallError> for Command {
    fn from(error: SyscallError) -> Self {
        Self::Syscall(error)
    }
}

impl From<CStrBufferTooSmall> for Command {
    fn from(_: CStrBufferTooSmall) -> Self {
        Self::CStrBufferTooSmall
    }
}

impl From<std::ffi::NulError> for Command {
    fn from(error: std::ffi::NulError) -> Self {
        Self::NulError(error)
    }
}
