// SPDX-License-Identifier: AGPL-3.0-only

//! Specialized error type for Linux backend procedures.

use meowix::errors::SyscallError;

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
}

impl From<SyscallError> for Command {
    fn from(error: SyscallError) -> Self {
        Self::Syscall(error)
    }
}
