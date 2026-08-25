// SPDX-License-Identifier: AGPL-3.0-only

//! Error representation for syscalls and netlink calls.

use core::{error, fmt};

#[cfg(feature = "alloc")]
use alloc::string::FromUtf8Error;

use super::errno::Errno;

/// Enumeration over errors that may occur while using netlink.
#[non_exhaustive]
#[derive(Copy, Clone, Debug)]
pub enum Netlink {
    /// Malformed header in a netlink message.
    MalformedHeader,

    /// Truncated netlink message.
    TruncatedMessage,

    /// Mismatched sequence number.
    SequenceMismatch,

    /// Incorrect size.
    IncorrectSize,

    /// Fixed-size buffer was too small to contain something.
    BufferTooSmall,

    /// Fixed-width integer would have overflowed.
    IntegerOverflow,

    /// A write was incomplete.
    IncompleteWrite,

    /// Timed out while waiting for ACK.
    AckTimeout,

    /// Errno value.
    Errno(Errno),

    /// Syscall error.
    Syscall(SyscallError),
}

impl fmt::Display for Netlink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedHeader => {
                f.write_str("malformed header in netlink message")
            }
            Self::TruncatedMessage => {
                f.write_str("netlink message was truncated")
            }
            Self::SequenceMismatch => {
                f.write_str("netlink message had a mismatched sequence number")
            }
            Self::IncorrectSize => {
                f.write_str("netlink message was of the incorrect size")
            }
            Self::BufferTooSmall => {
                f.write_str("a fixed-size buffer was too small")
            }
            Self::IntegerOverflow => {
                f.write_str("a fixed-width integer would have overflowed")
            }
            Self::IncompleteWrite => f.write_str("a write was incomplete"),
            Self::AckTimeout => {
                f.write_str("timed out while waiting for an ACK")
            }
            Self::Errno(e) => write!(f, "netlink error: {e}"),
            Self::Syscall(e) => write!(f, "syscall error: {e}"),
        }
    }
}

impl error::Error for Netlink {}

impl From<IncompleteWrite> for Netlink {
    fn from(_: IncompleteWrite) -> Self {
        Self::IncompleteWrite
    }
}

impl From<Errno> for Netlink {
    fn from(error: Errno) -> Self {
        Self::Errno(error)
    }
}

impl From<SyscallError> for Netlink {
    fn from(error: SyscallError) -> Self {
        Self::Syscall(error)
    }
}

/// Specialized syscall error wrapper for tagging plain error values with the
/// syscallbeing called.
#[derive(Copy, Clone, Debug)]
pub struct SyscallError {
    /// Syscall being called.
    syscall: Syscall,

    /// Error value.
    error: Errno,
}

impl SyscallError {
    /// Create a new syscall error from a syscall value and an error.
    #[inline]
    pub const fn new(syscall: Syscall, error: Errno) -> Self {
        Self { syscall, error }
    }

    /// Get the syscall associated with the syscall error.
    #[inline]
    pub const fn syscall(self) -> Syscall {
        self.syscall
    }

    /// Get the error value associated with the syscall error.
    #[inline]
    pub const fn error(self) -> Errno {
        self.error
    }
}

impl fmt::Display for SyscallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "encountered {} while calling {}",
            self.error, self.syscall
        )
    }
}

impl error::Error for SyscallError {}

/// Extension trait for a [`Result`] containing an [`Errno`] that wraps the
/// error in a [`SyscallError`].
pub(crate) trait ResultErrnoExt<T>:
    Sized + Into<Result<T, Errno>>
{
    /// Wraps the error with an annotation about which syscall it originated
    /// from.
    fn wrap_syscall(self, syscall: Syscall) -> Result<T, SyscallError> {
        self.into().map_err(|error| SyscallError { syscall, error })
    }
}

impl<T> ResultErrnoExt<T> for Result<T, Errno> {}

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

    /// `recvmsg(2)`.
    Recvmsg = 32,

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

    /// `gettid(2)`.
    Gettid = 39,

    /// `pidfd_send_signal(2)`.
    PidfdSendSignal = 40,

    /// `umask(2)`.
    Umask = 41,

    /// `waitid(2)`.
    Waitid = 42,

    /// `execveat(2)`.
    Execveat = 43,

    /// `symlinkat(2)`.
    Symlinkat = 44,

    /// `fcntl(2)`.
    Fcntl = 45,

    /// Syscall variant was not recognized.
    Unknown = u8::MAX,
}

impl fmt::Display for Syscall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pipe2 => "pipe2(2)",
            Self::Clone3 => "clone3(2)",
            Self::Openat2 => "openat2(2)",
            Self::Write => "write(2)",
            Self::OpenTree => "open_tree(2)",
            Self::OpenTreeAttr => "open_tree_attr(2)",
            Self::Dup3 => "dup3(2)",
            Self::MountSetattr => "mount_setattr(2)",
            Self::Statx => "statx(2)",
            Self::Read => "read(2)",
            Self::Mkdirat => "mkdirat(2)",
            Self::Eventfd2 => "eventfd2(2)",
            Self::CloseRange => "close_range(2)",
            Self::Capset => "capset(2)",
            Self::Prctl => "prctl(2)",
            Self::Unshare => "unshare(2)",
            Self::Setsid => "setsid(2)",
            Self::Setdomainname => "setdomainname(2)",
            Self::Sethostname => "sethostname(2)",
            Self::Chdir => "chdir(2)",
            Self::Umount2 => "umount2(2)",
            Self::Chroot => "chroot(2)",
            Self::MoveMount => "move_mount(2)",
            Self::Fchdir => "fchdir(2)",
            Self::Fsmount => "fsmount(2)",
            Self::Fsconfig => "fsconfig(2)",
            Self::Fsopen => "fsopen(2)",
            Self::Mount => "mount(2)",
            Self::Setns => "setns(2)",
            Self::RtSigaction => "rt_sigaction(2)",
            Self::RtSigprocmask => "rt_sigprocmask(2)",
            Self::Ppoll => "ppoll(2)",
            Self::Recvmsg => "recvmsg(2)",
            Self::Sendto => "sendto(2)",
            Self::Socket => "socket(2)",
            Self::Ioctl => "ioctl(2)",
            Self::PidfdOpen => "pidfd_open(2)",
            Self::Getegid => "getegid(2)",
            Self::Geteuid => "geteuid(2)",
            Self::Gettid => "gettid(2)",
            Self::PidfdSendSignal => "pidfd_send_signal(2)",
            Self::Umask => "umask(2)",
            Self::Waitid => "waitid(2)",
            Self::Execveat => "execveat(2)",
            Self::Symlinkat => "symlinkat(2)",
            Self::Fcntl => "fcntl(2)",
            Self::Unknown => "unknown syscall",
        })
    }
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
            32 => Syscall::Recvmsg,
            33 => Syscall::Sendto,
            34 => Syscall::Socket,
            35 => Syscall::Ioctl,
            36 => Syscall::PidfdOpen,
            37 => Syscall::Getegid,
            38 => Syscall::Geteuid,
            39 => Syscall::Gettid,
            40 => Syscall::PidfdSendSignal,
            41 => Syscall::Umask,
            42 => Syscall::Waitid,
            43 => Syscall::Execveat,
            44 => Syscall::Symlinkat,
            45 => Syscall::Fcntl,
            _ => Syscall::Unknown,
        }
    }
}

/// An [`core::ffi::CStr`] conversion buffer was too small.
#[derive(Copy, Clone, Debug)]
pub struct CStrBufferTooSmall;

impl fmt::Display for CStrBufferTooSmall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a buffer used for C string conversion was too small")
    }
}

impl error::Error for CStrBufferTooSmall {}

/// Indicates that a write was not complete.
#[derive(Copy, Clone, Debug)]
pub struct IncompleteWrite;

impl fmt::Display for IncompleteWrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a write was incomplete")
    }
}

impl error::Error for IncompleteWrite {}

/// Error that may be converted to by [`CStrBufferTooSmall`] and
/// [`core::ffi::FromBytesWithNulError`] for convenience.
#[derive(Copy, Clone, Debug)]
pub enum WithCStrError {
    /// [`core::ffi::CStr`] buffer was too small.
    CStrBufferTooSmall,

    /// Type being converted to a [`core::ffi::CStr`] was invalid.
    FromBytesWithNulError(core::ffi::FromBytesWithNulError),
}

impl fmt::Display for WithCStrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CStrBufferTooSmall => f.write_str(
                "a buffer used for C string conversion was too small",
            ),
            Self::FromBytesWithNulError(e) => {
                write!(f, "C string conversion error: {e}")
            }
        }
    }
}

impl error::Error for WithCStrError {}

impl From<CStrBufferTooSmall> for WithCStrError {
    fn from(_: CStrBufferTooSmall) -> Self {
        Self::CStrBufferTooSmall
    }
}

impl From<core::ffi::FromBytesWithNulError> for WithCStrError {
    fn from(error: core::ffi::FromBytesWithNulError) -> Self {
        Self::FromBytesWithNulError(error)
    }
}

/// Error that contains the number of bytes transferred for partial reads and
/// writes.
#[derive(Copy, Clone, Debug)]
pub struct PartialTransfer {
    /// Number of bytes transferred.
    pub transferred: usize,

    /// Error that occurred.
    pub error: Option<SyscallError>,
}

impl fmt::Display for PartialTransfer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(error) = self.error {
            write!(
                f,
                "partial transfer of only {} bytes: {error}",
                self.transferred
            )
        } else {
            write!(f, "partial transfer of only {} bytes", self.transferred)
        }
    }
}

impl error::Error for PartialTransfer {}

/// Error that may be either a [`SyscallError`] or a [`FromUtf8Error`].
#[cfg(feature = "alloc")]
#[derive(Clone, Debug)]
pub enum StringRead {
    /// Syscall error.
    Syscall(SyscallError),

    /// UTF-8 conversion error.
    Utf8(FromUtf8Error),
}

#[cfg(feature = "alloc")]
impl fmt::Display for StringRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syscall(e) => write!(f, "syscall error: {e}"),
            Self::Utf8(e) => write!(f, "UTF-8 conversion error: {e}"),
        }
    }
}

#[cfg(feature = "alloc")]
impl error::Error for StringRead {}

#[cfg(feature = "alloc")]
impl From<SyscallError> for StringRead {
    fn from(error: SyscallError) -> Self {
        Self::Syscall(error)
    }
}

#[cfg(feature = "alloc")]
impl From<FromUtf8Error> for StringRead {
    fn from(error: FromUtf8Error) -> Self {
        Self::Utf8(error)
    }
}
