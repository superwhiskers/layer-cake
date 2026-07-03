// SPDX-License-Identifier: AGPL-3.0-only

//! Specialized error type for Linux backend procedures.

use super::syscalls;

/// Enumeration over errors surfaced by the bubblebox Linux backend.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// Frontend error.
    Frontend(Frontend),

    /// Pre-`clone3(2)` error.
    PreClone(PreClone),

    /// Post-`clone3(2)` error from the host.
    PostCloneHost(PostCloneHost),

    /// Post-`clone3(2)` error from the guest.
    PostCloneGuest(PostCloneGuest),
}

impl From<Frontend> for Error {
    fn from(error: Frontend) -> Self {
        Self::Frontend(error)
    }
}

impl From<PreClone> for Error {
    fn from(error: PreClone) -> Self {
        Self::PreClone(error)
    }
}

impl From<PostCloneHost> for Error {
    fn from(error: PostCloneHost) -> Self {
        Self::PostCloneHost(error)
    }
}

impl From<PostCloneGuest> for Error {
    fn from(error: PostCloneGuest) -> Self {
        Self::PostCloneGuest(error)
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

/// Enumeration over errors that may occur in frontend code.
#[non_exhaustive]
#[derive(Debug)]
pub enum Frontend {
    /// A syscall failed.
    Syscall(SyscallError),

    /// File did not turn out to be a file.
    NotAFile,

    /// Directory did not turn out to be a directory.
    NotADirectory,

    /// Buffer used for C string conversion was too small.
    CStrBufferTooSmall,

    /// A string being converted to a C string contained a null byte.
    FromBytesWithNulError(std::ffi::FromBytesWithNulError),
}

impl From<SyscallError> for Frontend {
    fn from(error: SyscallError) -> Self {
        Self::Syscall(error)
    }
}

impl From<CStrBufferTooSmall> for Frontend {
    fn from(_: CStrBufferTooSmall) -> Self {
        Self::CStrBufferTooSmall
    }
}

impl From<std::ffi::FromBytesWithNulError> for Frontend {
    fn from(error: std::ffi::FromBytesWithNulError) -> Self {
        Self::FromBytesWithNulError(error)
    }
}

/// Enumeration over errors that may occur after calling `clone3(2)` in the host
/// process within the bubblebox Linux backend.
#[non_exhaustive]
#[derive(Debug)]
pub enum PostCloneHost {
    /// A syscall failed.
    Syscall(SyscallError),

    /// A standard library I/O operation failed.
    StdIo(std::io::Error),

    /// A D-Bus operation failed.
    #[cfg(feature = "systemd-cgroups")]
    Dbus(dbus::Error),

    /// Buffer used for C string conversion was too small.
    #[cfg(feature = "systemd-cgroups")]
    CStrBufferTooSmall,

    /// A string being converted to a C string contained a null byte.
    #[cfg(feature = "systemd-cgroups")]
    FromBytesWithNulError(std::ffi::FromBytesWithNulError),

    /// A write was incomplete.
    IncompleteWrite,

    /// Invalid state was entered in cgroups initialization code.
    InvalidCgroupsState,

    /// An error occurred on the host.
    Host(Host),
}

impl From<SyscallError> for PostCloneHost {
    fn from(error: SyscallError) -> Self {
        Self::Syscall(error)
    }
}

impl From<std::io::Error> for PostCloneHost {
    fn from(error: std::io::Error) -> Self {
        Self::StdIo(error)
    }
}

#[cfg(feature = "systemd-cgroups")]
impl From<dbus::Error> for PostCloneHost {
    fn from(error: dbus::Error) -> Self {
        Self::Dbus(error)
    }
}

#[cfg(feature = "systemd-cgroups")]
impl From<CStrBufferTooSmall> for PostCloneHost {
    fn from(_: CStrBufferTooSmall) -> Self {
        Self::CStrBufferTooSmall
    }
}

#[cfg(feature = "systemd-cgroups")]
impl From<std::ffi::FromBytesWithNulError> for PostCloneHost {
    fn from(error: std::ffi::FromBytesWithNulError) -> Self {
        Self::FromBytesWithNulError(error)
    }
}

impl From<IncompleteWrite> for PostCloneHost {
    fn from(_: IncompleteWrite) -> Self {
        Self::IncompleteWrite
    }
}

impl From<Host> for PostCloneHost {
    fn from(error: Host) -> Self {
        Self::Host(error)
    }
}

/// Enumeration over errors that may be ordered either before or after
/// `clone3(2)` but must happen on the host.
#[non_exhaustive]
#[derive(Debug)]
pub enum Host {
    /// Syscall failed.
    Syscall(SyscallError),

    /// Standard library I/O operation failed.
    StdIo(std::io::Error),

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

impl From<std::io::Error> for Host {
    fn from(error: std::io::Error) -> Self {
        Self::StdIo(error)
    }
}

impl From<IncompleteWrite> for Host {
    fn from(_: IncompleteWrite) -> Self {
        Self::IncompleteWrite
    }
}

/// Enumeration over errors that may occur prior to calling `clone3(2)` in the
/// bubblebox Linux backend.
#[non_exhaustive]
#[derive(Debug)]
pub enum PreClone {
    /// File descriptor policy was invalid.
    InvalidFdPolicy,

    /// Mappings were invalid.
    InvalidMappings,

    /// A syscall failed.
    Syscall(SyscallError),

    /// An error occurred on the host.
    Host(Host),
}

impl From<SyscallError> for PreClone {
    fn from(error: SyscallError) -> Self {
        Self::Syscall(error)
    }
}

impl From<Host> for PreClone {
    fn from(error: Host) -> Self {
        Self::Host(error)
    }
}

/// Enumeration over errors that may occur after calling `clone3(2)` in the
/// guest process within the bubblebox Linux backend.
#[non_exhaustive]
#[derive(Debug)]
pub enum PostCloneGuest {
    /// A syscall failed.
    Syscall(SyscallError),

    /// A standard library I/O operation failed.
    StdIo(std::io::Error),

    /// An error from netlink.
    Netlink(Netlink),

    /// Any other error.
    Other(PostCloneGuestOther),

    /// A write was incomplete.
    IncompleteWrite,

    /// A [`std::ffi::CStr`] conversion buffer was too small.
    CStrBufferTooSmall,

    /// A string being converted to a C string contained a null byte.
    FromBytesWithNulError,

    /// Unrecognized error from the wire format not originating from a
    /// [`Syscall`] variant.
    InvalidWireFormat,
}

impl From<SyscallError> for PostCloneGuest {
    fn from(error: SyscallError) -> Self {
        Self::Syscall(error)
    }
}

impl From<std::io::Error> for PostCloneGuest {
    fn from(error: std::io::Error) -> Self {
        Self::StdIo(error)
    }
}

impl From<Netlink> for PostCloneGuest {
    fn from(error: Netlink) -> Self {
        Self::Netlink(error)
    }
}

impl From<IncompleteWrite> for PostCloneGuest {
    fn from(_: IncompleteWrite) -> Self {
        Self::IncompleteWrite
    }
}

impl From<CStrBufferTooSmall> for PostCloneGuest {
    fn from(_: CStrBufferTooSmall) -> Self {
        Self::CStrBufferTooSmall
    }
}

impl From<std::ffi::FromBytesWithNulError> for PostCloneGuest {
    fn from(_: std::ffi::FromBytesWithNulError) -> Self {
        Self::FromBytesWithNulError
    }
}

impl From<PostCloneGuestOther> for PostCloneGuest {
    fn from(error: PostCloneGuestOther) -> Self {
        Self::Other(error)
    }
}

impl From<PostCloneGuestWire> for PostCloneGuest {
    fn from(
        PostCloneGuestWire { tag, subtag, value }: PostCloneGuestWire,
    ) -> Self {
        match tag {
            v if v == u8::MAX => PostCloneGuest::Syscall(SyscallError {
                syscall: subtag.into(),
                error: syscalls::Errno::from_raw_os_error(value),
            }),
            v if v == u8::MAX - 1 => {
                if subtag == 0 {
                    PostCloneGuest::StdIo(std::io::Error::from_raw_os_error(
                        value,
                    ))
                } else {
                    PostCloneGuest::StdIo(std::io::Error::other(
                        "error was not an os error",
                    ))
                }
            }
            v if v == u8::MAX - 2 => {
                if subtag == 0 {
                    PostCloneGuest::Netlink(match value {
                        1 => Netlink::MalformedHeader,
                        2 => Netlink::TruncatedMessage,
                        3 => Netlink::SequenceMismatch,
                        4 => Netlink::IncorrectSize,
                        _ => return PostCloneGuest::InvalidWireFormat,
                    })
                } else {
                    PostCloneGuest::Netlink(Netlink::Errno(
                        syscalls::Errno::from_raw_os_error(value),
                    ))
                }
            }
            v if v == u8::MAX - 3 => PostCloneGuest::IncompleteWrite,
            v if v == u8::MAX - 4 => PostCloneGuest::CStrBufferTooSmall,
            v if v == u8::MAX - 5 => PostCloneGuest::FromBytesWithNulError,
            //NOTE: indicates [`PostCloneGuestOther`]
            v => v.into(),
        }
    }
}

/// Enumeration over other errors that occur in the guest post-`clone3(2)`.
///
/// This is used to simplify manual discriminant handling in the wire format.
#[non_exhaustive]
#[derive(Debug)]
#[repr(u8)]
pub enum PostCloneGuestOther {
    /// Invalid state was entered in cgroups initialization code.
    InvalidCgroupsState = 0,

    /// Path lacked a file name.
    PathLackedFileName = 1,

    /// Path lacked a parent directory.
    PathLackedParentDirectory = 2,

    /// A fixed-size buffer was too small.
    BufferTooSmall = 3,

    /// Integer overflow.
    IntegerOverflow = 4,

    /// Invalid directory mount point.
    InvalidDirectoryMountPoint = 5,

    /// Invalid regular file mount point.
    InvalidRegularFileMountPoint = 6,

    /// A destination already existed.
    DestinationExists = 7,

    /// There was a mismatch between the number of mappings resolved and the
    /// length of the mappings vector.
    MappingsLengthMismatch = 8,

    /// The length of the resolved mappings vector was not zero when it should
    /// have been.
    NonzeroResolvedLen = 9,

    /// A bind-mapped file did not have the expected file identity.
    BindMappedFileMismatch = 10,
}

impl From<u8> for PostCloneGuest {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Other(PostCloneGuestOther::InvalidCgroupsState),
            1 => Self::Other(PostCloneGuestOther::PathLackedFileName),
            2 => Self::Other(PostCloneGuestOther::PathLackedParentDirectory),
            3 => Self::Other(PostCloneGuestOther::BufferTooSmall),
            4 => Self::Other(PostCloneGuestOther::IntegerOverflow),
            5 => Self::Other(PostCloneGuestOther::InvalidDirectoryMountPoint),
            6 => Self::Other(PostCloneGuestOther::InvalidRegularFileMountPoint),
            7 => Self::Other(PostCloneGuestOther::DestinationExists),
            8 => Self::Other(PostCloneGuestOther::MappingsLengthMismatch),
            9 => Self::Other(PostCloneGuestOther::NonzeroResolvedLen),
            10 => Self::Other(PostCloneGuestOther::BindMappedFileMismatch),
            _ => Self::InvalidWireFormat,
        }
    }
}

/// Enumeration over errors that may occur while using netlink.
#[non_exhaustive]
#[derive(Debug)]
pub enum Netlink {
    /// Malformed header in a netlink message.
    MalformedHeader,

    /// Truncated netlink message.
    TruncatedMessage,

    /// Mismatched sequence number.
    SequenceMismatch,

    /// Incorrect size.
    IncorrectSize,

    /// Errno value.
    Errno(syscalls::Errno),
}

impl From<syscalls::Errno> for Netlink {
    fn from(error: syscalls::Errno) -> Self {
        Self::Errno(error)
    }
}

/// Specialized syscall error wrapper for tagging plain error values with the
/// syscallbeing called.
#[derive(Copy, Clone, Debug)]
pub struct SyscallError {
    /// Syscall being called.
    pub(crate) syscall: Syscall,

    /// Error value.
    pub(crate) error: syscalls::Errno,
}

/// Enumeration over syscalls.
#[non_exhaustive]
#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum Syscall {
    /// `pipe2(2)`.
    Pipe2 = 0,

    /// `clone3(2)`.
    Clone3 = 1,

    /// `openat2(2)`.
    Openat2 = 2,

    /// `write(2)`.
    Write = 3,

    /// `open_tree(2)`.
    OpenTree = 4,

    /// `open_tree_attr(2)`.
    OpenTreeAttr = 5,

    /// `dup3(2)`.
    Dup3 = 6,

    /// `mount_setattr(2)`.
    MountSetattr = 7,

    /// `statx(2)`.
    Statx = 8,

    /// `read(2)`.
    Read = 9,

    /// `mkdirat(2)`.
    Mkdirat = 10,

    /// `eventfd2(2)`.
    Eventfd2 = 11,

    /// `close_range(2)`.
    CloseRange = 12,

    /// `capset(2)`.
    Capset = 13,

    /// `prctl(2)`.
    Prctl = 14,

    /// `unshare(2)`.
    Unshare = 15,

    /// `setsid(2)`.
    Setsid = 16,

    /// `setdomainname(2)`.
    Setdomainname = 17,

    /// `sethostname(2)`.
    Sethostname = 18,

    /// `chdir(2)`.
    Chdir = 19,

    /// `umount2(2)`.
    Umount2 = 20,

    /// `chroot(2)`.
    Chroot = 21,

    /// `move_mount(2)`.
    MoveMount = 22,

    /// `fchdir(2)`.
    Fchdir = 23,

    /// `fsmount(2)`.
    Fsmount = 24,

    /// `fsconfig(2)`.
    Fsconfig = 25,

    /// `fsopen(2)`.
    Fsopen = 26,

    /// `mount(2)`.
    Mount = 27,

    /// `setns(2)`.
    Setns = 28,

    /// `rt_sigaction(2)`.
    RtSigaction = 29,

    /// `rt_sigprocmask(2)`.
    RtSigprocmask = 30,

    /// `ppoll(2)`.
    Ppoll = 31,

    /// `recvfrom(2)`.
    Recvfrom = 32,

    /// `sendto(2)`.
    Sendto = 33,

    /// `socket(2)`.
    Socket = 34,

    /// `ioctl(2)`.
    Ioctl = 35,

    /// `pidfd_open(2)`.
    PidfdOpen = 36,

    /// `getegid(2)`.
    Getegid = 37,

    /// `geteuid(2)`.
    Geteuid = 38,

    /// `getpid(2)`.
    Getpid = 39,

    /// `pidfd_send_signal(2)`.
    PidfdSendSignal = 40,

    /// `umask(2)`.
    Umask = 41,

    /// `waitid(2)`.
    Waitid = 42,

    /// Syscall variant was not recognized.
    Unknown = u8::MAX,
}

impl From<u8> for Syscall {
    fn from(value: u8) -> Self {
        match value {
            0 => Syscall::Pipe2,
            1 => Syscall::Clone3,
            2 => Syscall::Openat2,
            3 => Syscall::Write,
            4 => Syscall::OpenTree,
            5 => Syscall::OpenTreeAttr,
            6 => Syscall::Dup3,
            7 => Syscall::MountSetattr,
            8 => Syscall::Statx,
            9 => Syscall::Read,
            10 => Syscall::Mkdirat,
            11 => Syscall::Eventfd2,
            12 => Syscall::CloseRange,
            13 => Syscall::Capset,
            14 => Syscall::Prctl,
            15 => Syscall::Unshare,
            16 => Syscall::Setsid,
            17 => Syscall::Setdomainname,
            18 => Syscall::Sethostname,
            19 => Syscall::Chdir,
            20 => Syscall::Umount2,
            21 => Syscall::Chroot,
            22 => Syscall::MoveMount,
            23 => Syscall::Fchdir,
            24 => Syscall::Fsmount,
            25 => Syscall::Fsconfig,
            26 => Syscall::Fsopen,
            27 => Syscall::Mount,
            28 => Syscall::Setns,
            29 => Syscall::RtSigaction,
            30 => Syscall::RtSigprocmask,
            31 => Syscall::Ppoll,
            32 => Syscall::Recvfrom,
            33 => Syscall::Sendto,
            34 => Syscall::Socket,
            35 => Syscall::Ioctl,
            36 => Syscall::PidfdOpen,
            37 => Syscall::Getegid,
            38 => Syscall::Geteuid,
            39 => Syscall::Getpid,
            40 => Syscall::PidfdSendSignal,
            41 => Syscall::Umask,
            42 => Syscall::Waitid,
            _ => Syscall::Unknown,
        }
    }
}

/// Special error that occurs when a write was incomplete.
#[derive(Copy, Clone, Debug)]
pub struct IncompleteWrite;

/// Special error that occurs when the [`std::ffi::CStr`] conversion buffer was
/// too small.
#[derive(Copy, Clone, Debug)]
pub struct CStrBufferTooSmall;

/// Simplified post-`clone3(2)` guest error type for the wire format.
#[derive(Copy, Clone, Debug, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C, packed)]
pub struct PostCloneGuestWire {
    /// Which of the enum variants this corresponds to.
    tag: u8,

    /// If `tag` referred to a variant which contains another enum, which
    /// variant of that enum this corresponds to.
    subtag: u8,

    /// If `tag` or `subtag` referred to a variant which contains a value, the
    /// value contained within that variant.
    value: i32,
}

impl From<PostCloneGuest> for PostCloneGuestWire {
    fn from(error: PostCloneGuest) -> Self {
        match error {
            PostCloneGuest::Syscall(SyscallError { syscall, error }) => {
                PostCloneGuestWire {
                    tag: u8::MAX,
                    subtag: syscall as u8,
                    value: error.raw_os_error(),
                }
            }
            PostCloneGuest::StdIo(error) => {
                if let Some(raw) = error.raw_os_error() {
                    PostCloneGuestWire {
                        tag: u8::MAX - 1,
                        subtag: 0,
                        value: raw,
                    }
                } else {
                    //NOTE: we may lose some data here but i don't think this
                    //      is likely. additionally, `std::io` may be removed
                    //      from the child path anyway
                    PostCloneGuestWire {
                        tag: u8::MAX - 1,
                        subtag: 1,
                        value: 0,
                    }
                }
            }
            PostCloneGuest::Netlink(netlink_error) => {
                let (subtag, value) = match netlink_error {
                    Netlink::MalformedHeader => (0, 1),
                    Netlink::TruncatedMessage => (0, 2),
                    Netlink::SequenceMismatch => (0, 3),
                    Netlink::IncorrectSize => (0, 4),
                    Netlink::Errno(error) => (1, error.raw_os_error()),
                };

                PostCloneGuestWire {
                    tag: u8::MAX - 2,
                    subtag,
                    value,
                }
            }
            PostCloneGuest::IncompleteWrite => PostCloneGuestWire {
                tag: u8::MAX - 3,
                subtag: 0,
                value: 0,
            },
            PostCloneGuest::CStrBufferTooSmall => PostCloneGuestWire {
                tag: u8::MAX - 4,
                subtag: 0,
                value: 0,
            },
            PostCloneGuest::FromBytesWithNulError => PostCloneGuestWire {
                tag: u8::MAX - 5,
                subtag: 0,
                value: 0,
            },
            //NOTE: we don't need to handle this in the parse step because any
            //      unrecognized tag gets parsed as this
            PostCloneGuest::InvalidWireFormat => PostCloneGuestWire {
                tag: u8::MAX - 6,
                subtag: 0,
                value: 0,
            },
            PostCloneGuest::Other(e) => {
                //NOTE: this is okay as long as we don't come into contact with
                //      the other end
                PostCloneGuestWire {
                    tag: e as u8,
                    subtag: 0,
                    value: 0,
                }
            }
        }
    }
}

/// Extension trait for [`syscalls::Errno`] that wraps the value in a
/// [`SyscallError`].
pub(crate) trait ErrnoExt: Sized + Into<syscalls::Errno> {
    /// Wraps the syscall error with an annotation about which syscall it
    /// originated from.
    fn attach_syscall(self, syscall: Syscall) -> SyscallError {
        SyscallError {
            syscall,
            error: self.into(),
        }
    }
}

impl ErrnoExt for syscalls::Errno {}

/// Extension trait for [`Result<T, syscalls::Errno>`] that wraps the error in
/// a [`SyscallError`].
pub(crate) trait ResultErrnoExt<T>:
    Sized + Into<Result<T, syscalls::Errno>>
{
    /// Wraps the error with an annotation about which syscall it originated
    /// from.
    fn wrap_syscall(self, syscall: Syscall) -> Result<T, SyscallError> {
        self.into().map_err(|e| e.attach_syscall(syscall))
    }
}

impl<T> ResultErrnoExt<T> for Result<T, syscalls::Errno> {}

/// Extension trait for [`Result<T, syscalls::Errno>`] that makes tagging
/// errors simpler.
pub(crate) trait ResultExt<T>:
    Sized + Into<Result<T, syscalls::Errno>>
{
    /// Wraps the error with an annotation about which syscall it originated
    /// from and the phase it was called in.
    fn wrap<I>(self, syscall: Syscall) -> Result<T, Error>
    where
        SyscallError: Into<I>,
        I: Into<Error>,
    {
        self.into()
            .map_err(|e| e.attach_syscall(syscall))
            .map_err(Tag::tag_with::<I>)
    }
}

impl<T> ResultExt<T> for Result<T, syscalls::Errno> {}

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
