// SPDX-License-Identifier: AGPL-3.0-only

//! Error types surfaced during sandbox spawn.

use meowix::{
    errno::Errno,
    errors::{
        CStrBufferTooSmall, IncompleteWrite, Netlink, StringRead, SyscallError,
    },
};

use super::wire::PostSpawnGuestWire;

/// Enumeration over errors that may occur prior to spawning the guest in the
/// bubblebox Linux backend.
#[non_exhaustive]
#[derive(Debug)]
pub enum PreSpawn {
    /// A syscall failed.
    Syscall(SyscallError),

    /// An error occurred on the host.
    Host(Host),
}

impl From<SyscallError> for PreSpawn {
    fn from(error: SyscallError) -> Self {
        Self::Syscall(error)
    }
}

impl From<Host> for PreSpawn {
    fn from(error: Host) -> Self {
        Self::Host(error)
    }
}

/// Enumeration over errors that originate from the host after it has spawned
/// the guest process within the bubblebox Linux backend.
#[non_exhaustive]
#[derive(Debug)]
pub enum PostSpawnHost {
    /// A syscall failed.
    Syscall(SyscallError),

    /// A D-Bus operation failed.
    #[cfg(feature = "systemd-cgroups")]
    Dbus(dbus::Error),

    /// Buffer used for C string conversion was too small.
    #[cfg(feature = "systemd-cgroups")]
    CStrBufferTooSmall,

    /// A string being converted to a C string contained a null byte.
    #[cfg(feature = "systemd-cgroups")]
    FromBytesWithNulError(std::ffi::FromBytesWithNulError),

    /// Casting the child error information failed.
    PodCastError(bytemuck::PodCastError),

    /// A write was incomplete.
    IncompleteWrite,

    /// Invalid state was entered in cgroups initialization code.
    InvalidCgroupsState,

    /// An error occurred on the host.
    Host(Host),
}

impl From<SyscallError> for PostSpawnHost {
    fn from(error: SyscallError) -> Self {
        Self::Syscall(error)
    }
}

#[cfg(feature = "systemd-cgroups")]
impl From<dbus::Error> for PostSpawnHost {
    fn from(error: dbus::Error) -> Self {
        Self::Dbus(error)
    }
}

#[cfg(feature = "systemd-cgroups")]
impl From<CStrBufferTooSmall> for PostSpawnHost {
    fn from(_: CStrBufferTooSmall) -> Self {
        Self::CStrBufferTooSmall
    }
}

#[cfg(feature = "systemd-cgroups")]
impl From<std::ffi::FromBytesWithNulError> for PostSpawnHost {
    fn from(error: std::ffi::FromBytesWithNulError) -> Self {
        Self::FromBytesWithNulError(error)
    }
}

impl From<bytemuck::PodCastError> for PostSpawnHost {
    fn from(error: bytemuck::PodCastError) -> Self {
        Self::PodCastError(error)
    }
}

impl From<IncompleteWrite> for PostSpawnHost {
    fn from(_: IncompleteWrite) -> Self {
        Self::IncompleteWrite
    }
}

impl From<Host> for PostSpawnHost {
    fn from(error: Host) -> Self {
        Self::Host(error)
    }
}

/// Enumeration over errors that may be ordered before or after spawning the
/// guest but must originate from the host.
#[non_exhaustive]
#[derive(Debug)]
pub enum Host {
    /// Syscall failed.
    Syscall(SyscallError),

    /// Reading from an fd into a [`String`] failed.
    StringRead(StringRead),

    /// Write was incomplete.
    IncompleteWrite,

    /// Requested cgroup controller was missing.
    //TODO: this should be an enum
    MissingCgroupController(&'static str),
}

impl From<SyscallError> for Host {
    fn from(error: SyscallError) -> Self {
        Self::Syscall(error)
    }
}

impl From<StringRead> for Host {
    fn from(error: StringRead) -> Self {
        Self::StringRead(error)
    }
}

impl From<IncompleteWrite> for Host {
    fn from(_: IncompleteWrite) -> Self {
        Self::IncompleteWrite
    }
}

/// Enumeration over errors that originate from the guest after it has been
/// spawned in the bubblebox Linux backend.
#[non_exhaustive]
#[derive(Debug)]
pub enum PostSpawnGuest {
    /// A syscall failed.
    Syscall(SyscallError),

    /// An error from netlink.
    Netlink(Netlink),

    /// Any other error.
    Other(PostSpawnGuestOther),

    /// A write was incomplete.
    IncompleteWrite,

    /// A [`std::ffi::CStr`] conversion buffer was too small.
    CStrBufferTooSmall,

    /// A string being converted to a C string contained a null byte.
    FromBytesWithNulError,

    /// Unrecognized error from the wire format not originating from a syscall
    /// variant.
    InvalidWireFormat,
}

impl From<SyscallError> for PostSpawnGuest {
    fn from(error: SyscallError) -> Self {
        Self::Syscall(error)
    }
}

impl From<Netlink> for PostSpawnGuest {
    fn from(error: Netlink) -> Self {
        Self::Netlink(error)
    }
}

impl From<IncompleteWrite> for PostSpawnGuest {
    fn from(_: IncompleteWrite) -> Self {
        Self::IncompleteWrite
    }
}

impl From<CStrBufferTooSmall> for PostSpawnGuest {
    fn from(_: CStrBufferTooSmall) -> Self {
        Self::CStrBufferTooSmall
    }
}

impl From<std::ffi::FromBytesWithNulError> for PostSpawnGuest {
    fn from(_: std::ffi::FromBytesWithNulError) -> Self {
        Self::FromBytesWithNulError
    }
}

impl From<PostSpawnGuestOther> for PostSpawnGuest {
    fn from(error: PostSpawnGuestOther) -> Self {
        Self::Other(error)
    }
}

impl From<PostSpawnGuestWire> for PostSpawnGuest {
    fn from(
        PostSpawnGuestWire { tag, subtag, value }: PostSpawnGuestWire,
    ) -> Self {
        match tag {
            v if v == u8::MAX => PostSpawnGuest::Syscall(SyscallError::new(
                subtag.into(),
                Errno::from_raw_os_error(value),
            )),
            v if v == u8::MAX - 1 => {
                if subtag == 0 {
                    PostSpawnGuest::Netlink(match value {
                        1 => Netlink::MalformedHeader,
                        2 => Netlink::TruncatedMessage,
                        3 => Netlink::SequenceMismatch,
                        4 => Netlink::IncorrectSize,
                        5 => Netlink::BufferTooSmall,
                        6 => Netlink::IntegerOverflow,
                        7 => Netlink::IncompleteWrite,
                        _ => return PostSpawnGuest::InvalidWireFormat,
                    })
                } else if subtag == u8::MAX {
                    PostSpawnGuest::Netlink(Netlink::Errno(
                        Errno::from_raw_os_error(value),
                    ))
                } else {
                    PostSpawnGuest::Netlink(Netlink::Syscall(
                        SyscallError::new(
                            subtag.into(),
                            Errno::from_raw_os_error(value),
                        ),
                    ))
                }
            }
            v if v == u8::MAX - 2 => PostSpawnGuest::IncompleteWrite,
            v if v == u8::MAX - 3 => PostSpawnGuest::CStrBufferTooSmall,
            v if v == u8::MAX - 4 => PostSpawnGuest::FromBytesWithNulError,
            //NOTE: indicates [`PostSpawnGuestOther`]
            v => v.into(),
        }
    }
}

/// Enumeration over other errors that occur in the guest post-spawn.
///
/// This is used to simplify manual discriminant handling in the wire format.
#[non_exhaustive]
#[derive(Debug)]
#[repr(u8)]
pub enum PostSpawnGuestOther {
    /// Invalid state was entered in cgroups initialization code.
    InvalidCgroupsState = 0,

    /// A fixed-size buffer was too small.
    BufferTooSmall = 1,

    /// Integer overflow.
    IntegerOverflow = 2,

    /// Invalid directory mount point.
    InvalidDirectoryMountPoint = 3,

    /// Invalid regular file mount point.
    InvalidRegularFileMountPoint = 4,

    /// A destination already existed.
    DestinationExists = 5,

    /// There was a mismatch between the number of mappings resolved and the
    /// length of the mappings vector.
    MappingsLengthMismatch = 6,

    /// The length of the resolved mappings vector was not zero when it should
    /// have been.
    NonzeroResolvedLen = 7,

    /// A bind-mapped file did not have the expected file identity.
    BindMappedFileMismatch = 8,
}

impl From<u8> for PostSpawnGuest {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Other(PostSpawnGuestOther::InvalidCgroupsState),
            1 => Self::Other(PostSpawnGuestOther::BufferTooSmall),
            2 => Self::Other(PostSpawnGuestOther::IntegerOverflow),
            3 => Self::Other(PostSpawnGuestOther::InvalidDirectoryMountPoint),
            4 => Self::Other(PostSpawnGuestOther::InvalidRegularFileMountPoint),
            5 => Self::Other(PostSpawnGuestOther::DestinationExists),
            6 => Self::Other(PostSpawnGuestOther::MappingsLengthMismatch),
            7 => Self::Other(PostSpawnGuestOther::NonzeroResolvedLen),
            8 => Self::Other(PostSpawnGuestOther::BindMappedFileMismatch),
            _ => Self::InvalidWireFormat,
        }
    }
}
