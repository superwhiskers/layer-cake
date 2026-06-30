// SPDX-License-Identifier: AGPL-3.0-only

//! Error handling and definitions used across bubblebox.

use rkyv::{Archive, Deserialize, Serialize};
use rustix::io::Errno;
use std::{
    ffi,
    io::{self, Error as IoError},
    num::ParseIntError,
};

/// Convenience alias for [`Result`]s returned by bubblebox procedures.
pub type Result<T> = std::result::Result<T, Error>;

/// Enumeration over errors surfaced by bubblebox.
#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The given path was not absolute.
    #[error("The provided path was not absolute")]
    PathNotAbsolute,

    /// The given path contained a reference to the parent.
    #[error("The provided path contained a reference to a parent path")]
    PathContainsParent,

    /// The given guest path contained a Windows path prefix.
    #[error("The provided guest path contained a Windows path prefix")]
    GuestPathHasPrefix,

    /// The file descriptor policy is invalid.
    #[error("The provided file descriptor policy is invalid")]
    InvalidFdPolicy,

    /// The mappings are invalid.
    #[error("The provided mappings are invalid")]
    InvalidMappings,

    /// An invalid state occurred.
    #[error("An invalid state occurred")]
    InvalidState,

    /// The given path was not to a file.
    #[error("The given path was not to a file")]
    NotAFile,

    /// The given path was not to a directory.
    #[error("The given path was not to a directory")]
    NotADirectory,

    /// An I/O error occurred.
    #[error("An I/O error occurred")]
    Io(#[from] IoError),

    /// An error occurred in an OS system call.
    #[error("An OS error occurred")]
    Errno(#[from] Errno),

    /// An error occurred while parsing an integer.
    #[error("Parsing of an integer literal failed")]
    ParseIntError(#[from] ParseIntError),

    /// A cgroup controller requested was missing.
    //TODO: replace with enum?
    #[error(
        "The `{0}` cgroup controller was requested in the policy but missing"
    )]
    MissingCgroupController(&'static str),

    /// An error occurred after the child process handoff.
    #[error("An error occurred in the child process")]
    Child(#[from] ChildError),

    /// An error occurred in rkyv.
    #[error("An error occurred in the rkyv library")]
    Rkyv(#[from] rkyv::rancor::Error),

    /// An error occurred while working with D-Bus.
    #[cfg(feature = "systemd-cgroups")]
    #[error("An error occurred while working with D-Bus")]
    Dbus(#[from] dbus::Error),
}

/// Simplified error type for the child process.
#[non_exhaustive]
#[derive(thiserror::Error, Archive, Serialize, Deserialize, Debug)]
pub enum ChildError {
    /// Rustix raw operating system error type.
    #[error("An error occurred while interacting with the operating system")]
    RustixOsError(i32),

    /// Standard library raw operating system error type.
    #[error("An error occurred while interacting with the operating system")]
    StdOsError(io::RawOsError),

    /// An incomplete write occurred where one should not have.
    #[error("An incomplete write occurred where one should not have")]
    IncompleteWrite,

    /// An invalid state occurred.
    #[error("An invalid state occurred")]
    InvalidState,

    /// An unspecified I/O error occurred.
    #[error("An unspecified I/O error occurred")]
    StdIoError,

    /// A static buffer was too small to contain the data.
    #[error("A static buffer was too small to contain the data")]
    BufferTooSmall,

    /// An integer overflow would have occurred.
    #[error("An integer overflow would have occurred")]
    IntegerOverflow,

    /// A mount point existed and wasn't a regular file.
    #[error("A mount point for a regular file wasn't a regular file")]
    InvalidRegularFileMountPoint,

    /// A mount point existed and wasn't a directory.
    #[error("A mount point for a directory wasn't a directory")]
    InvalidDirectoryMountPoint,

    /// The given path was just a filename or was empty.
    #[error("The provided path lacked any parent directory")]
    PathLackedParentDir,

    /// The given path lacked a file name.
    #[error("The provided path lacked a file name")]
    PathLackedFileName,

    /// A synthetic mount destination already existed.
    #[error(
        "A synthetic mount destination already existed. This restriction may be relaxed in the future"
    )]
    DestinationExisted,

    /// A netlink reply had a malformed header.
    #[error("A netlink reply had a malformed header")]
    NetlinkMalformedHeader,

    /// A netlink reply was truncated.
    #[error("A netlink reply was truncated")]
    NetlinkTruncatedMessage,

    /// A netlink reply had an incorrect size.
    #[error("A netlink reply had an incorrect size")]
    NetlinkIncorrectSize,

    /// A netlink reply had an unexpected sequence number.
    #[error("A netlink reply had an unexpected sequence number")]
    NetlinkSequenceMismatch,

    /// A netlink reply had an error.
    #[error("A netlink reply had an error")]
    NetlinkError(ffi::c_int),

    /// The error was unable to be parsed.
    ///
    /// We provide the first byte of the error data in this instance. If it is
    /// `0xE`, then the child likely encountered an error parsing.
    #[error(
        "The error failed to parse. The child may have been unable to serialize the error."
    )]
    UnspecifiedError(Option<u8>),
}

impl From<Errno> for ChildError {
    fn from(e: Errno) -> Self {
        Self::RustixOsError(e.raw_os_error())
    }
}

impl From<IoError> for ChildError {
    fn from(e: IoError) -> Self {
        if let Some(e) = e.raw_os_error() {
            Self::StdOsError(e)
        } else {
            Self::StdIoError
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rkyv::{
        Serialize,
        api::serialize_using,
        rancor::{Failure, Strategy},
        ser::{
            Serializer,
            allocator::{AllocationStats, AllocationTracker, SubAllocator},
            sharing::Unshare,
            writer::Buffer,
        },
        util::Align,
    };
    use std::mem::MaybeUninit;

    type TrackedSerializer<'a> = Strategy<
        Serializer<Buffer<'a>, AllocationTracker<SubAllocator<'a>>, Unshare>,
        Failure,
    >;

    #[test]
    fn buffer_size() {
        let mut output = Align([0; 1 << 5]);
        let mut scratch = Align([MaybeUninit::<u8>::uninit(); 1 << 5]);

        let mut serializer = Serializer::new(
            Buffer::from(&mut *output),
            AllocationTracker::new(SubAllocator::new(&mut *scratch)),
            Unshare,
        );

        let _ = serialize_using::<_, Failure>(
            &ChildError::RustixOsError(67),
            &mut serializer,
        )
        .expect("unable to serialize child error");

        let stats = serializer.into_raw_parts().1.into_stats();

        assert_eq!(
            (
                stats.min_arena_capacity(),
                stats.min_arena_capacity_max_error()
            ),
            (0, 0),
            "arena capacity should be 0 pm 0"
        );
        println!("{:?}", output);
    }
}
