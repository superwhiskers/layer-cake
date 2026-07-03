// SPDX-License-Identifier: AGPL-3.0-only

//! Direct syscall wrappers for syscalls.
//!
//! Originally, we used [`rustix`] for this purpose, but due to the hazard of
//! potentially allocating post-`clone3(2)`, we were forced to remove it.
//!
//! Because `cargo` will unify feature flags across the dependency tree, an
//! unrelated dependency introducing `std` to the feature flags of `rustix` may
//! cause allocations, which are not safe post-`clone3(2)`. Another reason
//! `rustix` was removed was that without the `std` feature flag, there is no
//! compatibility between its `fd` module and the standard library's module.
//!
//! [`rustix`]: https://github.com/bytecodealliance/rustix

//FIXME: remove this in the future once we have a better way of handling these
//       casts across architectures
#![allow(trivial_numeric_casts)]

use linux_raw_sys::{
    general::{self as linux, fsconfig_command as fsconfig},
    ioctl, net as linux_net, netlink, prctl,
};
use std::{
    borrow::Borrow,
    ffi::{self, CStr, OsStr},
    hint,
    marker::PhantomData,
    mem,
    num::NonZero,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    ptr,
};

use super::errors::{
    CStrBufferTooSmall, ResultErrnoExt, Syscall, SyscallError,
};

bitflags::bitflags! {
    /// Linux `CAP_*` constants.
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Debug)]
    pub struct CapabilitySet: u64 {
        /// `CAP_CHOWN`.
        const CHOWN = 1 << linux::CAP_CHOWN;

        /// `CAP_DAC_OVERRIDE`.
        const DAC_OVERRIDE = 1 << linux::CAP_DAC_OVERRIDE;

        /// `CAP_DAC_READ_SEARCH`.
        const DAC_READ_SEARCH = 1 << linux::CAP_DAC_READ_SEARCH;

        /// `CAP_FOWNER`.
        const FOWNER = 1 << linux::CAP_FOWNER;

        /// `CAP_FSETID`.
        const FSETID = 1 << linux::CAP_FSETID;

        /// `CAP_KILL`.
        const KILL = 1 << linux::CAP_KILL;

        /// `CAP_SETGID`.
        const SETGID = 1 << linux::CAP_SETGID;

        /// `CAP_SETUID`.
        const SETUID = 1 << linux::CAP_SETUID;

        /// `CAP_SETPCAP`.
        const SETPCAP = 1 << linux::CAP_SETPCAP;

        /// `CAP_LINUX_IMMUTABLE`.
        const LINUX_IMMUTABLE = 1 << linux::CAP_LINUX_IMMUTABLE;

        /// `CAP_NET_BIND_SERVICE`.
        const NET_BIND_SERVICE = 1 << linux::CAP_NET_BIND_SERVICE;

        /// `CAP_NET_BROADCAST`.
        const NET_BROADCAST = 1 << linux::CAP_NET_BROADCAST;

        /// `CAP_NET_ADMIN`.
        const NET_ADMIN = 1 << linux::CAP_NET_ADMIN;

        /// `CAP_NET_RAW`.
        const NET_RAW = 1 << linux::CAP_NET_RAW;

        /// `CAP_IPC_LOCK`.
        const IPC_LOCK = 1 << linux::CAP_IPC_LOCK;

        /// `CAP_IPC_OWNER`.
        const IPC_OWNER = 1 << linux::CAP_IPC_OWNER;

        /// `CAP_SYS_MODULE`.
        const SYS_MODULE = 1 << linux::CAP_SYS_MODULE;

        /// `CAP_SYS_RAWIO`.
        const SYS_RAWIO = 1 << linux::CAP_SYS_RAWIO;

        /// `CAP_SYS_CHROOT`.
        const SYS_CHROOT = 1 << linux::CAP_SYS_CHROOT;

        /// `CAP_SYS_PTRACE`.
        const SYS_PTRACE = 1 << linux::CAP_SYS_PTRACE;

        /// `CAP_SYS_PACCT`.
        const SYS_PACCT = 1 << linux::CAP_SYS_PACCT;

        /// `CAP_SYS_ADMIN`.
        const SYS_ADMIN = 1 << linux::CAP_SYS_ADMIN;

        /// `CAP_SYS_BOOT`.
        const SYS_BOOT = 1 << linux::CAP_SYS_BOOT;

        /// `CAP_SYS_NICE`.
        const SYS_NICE = 1 << linux::CAP_SYS_NICE;

        /// `CAP_SYS_RESOURCE`.
        const SYS_RESOURCE = 1 << linux::CAP_SYS_RESOURCE;

        /// `CAP_SYS_TIME`.
        const SYS_TIME = 1 << linux::CAP_SYS_TIME;

        /// `CAP_SYS_TTY_CONFIG`.
        const SYS_TTY_CONFIG = 1 << linux::CAP_SYS_TTY_CONFIG;

        /// `CAP_MKNOD`.
        const MKNOD = 1 << linux::CAP_MKNOD;

        /// `CAP_LEASE`.
        const LEASE = 1 << linux::CAP_LEASE;

        /// `CAP_AUDIT_WRITE`.
        const AUDIT_WRITE = 1 << linux::CAP_AUDIT_WRITE;

        /// `CAP_AUDIT_CONTROL`.
        const AUDIT_CONTROL = 1 << linux::CAP_AUDIT_CONTROL;

        /// `CAP_SETFCAP`.
        const SETFCAP = 1 << linux::CAP_SETFCAP;

        /// `CAP_MAC_OVERRIDE`.
        const MAC_OVERRIDE = 1 << linux::CAP_MAC_OVERRIDE;

        /// `CAP_MAC_ADMIN`.
        const MAC_ADMIN = 1 << linux::CAP_MAC_ADMIN;

        /// `CAP_SYSLOG`.
        const SYSLOG = 1 << linux::CAP_SYSLOG;

        /// `CAP_WAKE_ALARM`.
        const WAKE_ALARM = 1 << linux::CAP_WAKE_ALARM;

        /// `CAP_BLOCK_SUSPEND`.
        const BLOCK_SUSPEND = 1 << linux::CAP_BLOCK_SUSPEND;

        /// `CAP_AUDIT_READ`.
        const AUDIT_READ = 1 << linux::CAP_AUDIT_READ;

        /// `CAP_PERFMON`.
        const PERFMON = 1 << linux::CAP_PERFMON;

        /// `CAP_BPF`.
        const BPF = 1 << linux::CAP_BPF;

        /// `CAP_CHECKPOINT_RESTORE`.
        const CHECKPOINT_RESTORE = 1 << linux::CAP_CHECKPOINT_RESTORE;

        const _ = !0;
    }
}

macro_rules! errno_associated_const {
    ($name:ident, $error:ident) => {
        /// `
        #[doc = stringify!($error)]
        /// `
        pub const $name: Self = Self::from_errno(linux_raw_sys::errno::$error);
    };
}

/// Error value.
///
/// Akin to rustix, we store it negated to avoid the conversion cost from
/// syscalls.
#[derive(Eq, PartialEq, Hash, Copy, Clone, Debug)]
pub struct Errno(u16);

impl Errno {
    /// Extract the raw OS error number.
    #[inline]
    pub const fn raw_os_error(self) -> i32 {
        (self.0 as i16 as i32).wrapping_neg()
    }

    /// Construct an [`Errno`] from the given os error number.
    #[inline]
    pub const fn from_raw_os_error(raw: i32) -> Self {
        Self::from_errno(raw as u32)
    }

    /// Construct an [`Errno`] from a C errno.
    #[inline]
    const fn from_errno(raw: u32) -> Self {
        Self(raw.wrapping_neg() as u16)
    }

    errno_associated_const!(TOOBIG, E2BIG);
    errno_associated_const!(ACCESS, EACCES);
    errno_associated_const!(ADDRINUSE, EADDRINUSE);
    errno_associated_const!(ADDRNOTAVAIL, EADDRNOTAVAIL);
    errno_associated_const!(ADV, EADV);
    errno_associated_const!(AFNOSUPPORT, EAFNOSUPPORT);
    errno_associated_const!(AGAIN, EAGAIN);
    errno_associated_const!(ALREADY, EALREADY);
    errno_associated_const!(BADE, EBADE);
    errno_associated_const!(BADF, EBADF);
    errno_associated_const!(BADFD, EBADFD);
    errno_associated_const!(BADMSG, EBADMSG);
    errno_associated_const!(BADR, EBADR);
    errno_associated_const!(BADRQC, EBADRQC);
    errno_associated_const!(BADSLT, EBADSLT);
    errno_associated_const!(BFONT, EBFONT);
    errno_associated_const!(BUSY, EBUSY);
    errno_associated_const!(CANCELED, ECANCELED);
    errno_associated_const!(CHILD, ECHILD);
    errno_associated_const!(CHRNG, ECHRNG);
    errno_associated_const!(COMM, ECOMM);
    errno_associated_const!(CONNABORTED, ECONNABORTED);
    errno_associated_const!(CONNREFUSED, ECONNREFUSED);
    errno_associated_const!(CONNRESET, ECONNRESET);
    errno_associated_const!(DEADLK, EDEADLK);
    errno_associated_const!(DEADLOCK, EDEADLOCK);
    errno_associated_const!(DESTADDRREQ, EDESTADDRREQ);
    errno_associated_const!(DOM, EDOM);
    errno_associated_const!(DOTDOT, EDOTDOT);
    errno_associated_const!(DQUOT, EDQUOT);
    errno_associated_const!(EXIST, EEXIST);
    errno_associated_const!(FAULT, EFAULT);
    errno_associated_const!(FBIG, EFBIG);
    errno_associated_const!(HOSTDOWN, EHOSTDOWN);
    errno_associated_const!(HOSTUNREACH, EHOSTUNREACH);
    errno_associated_const!(HWPOISON, EHWPOISON);
    errno_associated_const!(IDRM, EIDRM);
    errno_associated_const!(ILSEQ, EILSEQ);
    errno_associated_const!(INPROGRESS, EINPROGRESS);
    errno_associated_const!(INTR, EINTR);
    errno_associated_const!(INVAL, EINVAL);
    errno_associated_const!(IO, EIO);
    errno_associated_const!(ISCONN, EISCONN);
    errno_associated_const!(ISDIR, EISDIR);
    errno_associated_const!(ISNAM, EISNAM);
    errno_associated_const!(KEYEXPIRED, EKEYEXPIRED);
    errno_associated_const!(KEYREJECTED, EKEYREJECTED);
    errno_associated_const!(KEYREVOKED, EKEYREVOKED);
    errno_associated_const!(L2HLT, EL2HLT);
    errno_associated_const!(L2NSYNC, EL2NSYNC);
    errno_associated_const!(L3HLT, EL3HLT);
    errno_associated_const!(L3RST, EL3RST);
    errno_associated_const!(LIBACC, ELIBACC);
    errno_associated_const!(LIBBAD, ELIBBAD);
    errno_associated_const!(LIBEXEC, ELIBEXEC);
    errno_associated_const!(LIBMAX, ELIBMAX);
    errno_associated_const!(LIBSCN, ELIBSCN);
    errno_associated_const!(LNRNG, ELNRNG);
    errno_associated_const!(LOOP, ELOOP);
    errno_associated_const!(MEDIUMTYPE, EMEDIUMTYPE);
    errno_associated_const!(MFILE, EMFILE);
    errno_associated_const!(MLINK, EMLINK);
    errno_associated_const!(MSGSIZE, EMSGSIZE);
    errno_associated_const!(MULTIHOP, EMULTIHOP);
    errno_associated_const!(NAMETOOLONG, ENAMETOOLONG);
    errno_associated_const!(NAVAIL, ENAVAIL);
    errno_associated_const!(NETDOWN, ENETDOWN);
    errno_associated_const!(NETRESET, ENETRESET);
    errno_associated_const!(NETUNREACH, ENETUNREACH);
    errno_associated_const!(NFILE, ENFILE);
    errno_associated_const!(NOANO, ENOANO);
    errno_associated_const!(NOBUFS, ENOBUFS);
    errno_associated_const!(NOCSI, ENOCSI);
    errno_associated_const!(NODATA, ENODATA);
    errno_associated_const!(NODEV, ENODEV);
    errno_associated_const!(NOENT, ENOENT);
    errno_associated_const!(NOEXEC, ENOEXEC);
    errno_associated_const!(NOKEY, ENOKEY);
    errno_associated_const!(NOLCK, ENOLCK);
    errno_associated_const!(NOLINK, ENOLINK);
    errno_associated_const!(NOMEDIUM, ENOMEDIUM);
    errno_associated_const!(NOMEM, ENOMEM);
    errno_associated_const!(NOMSG, ENOMSG);
    errno_associated_const!(NONET, ENONET);
    errno_associated_const!(NOPKG, ENOPKG);
    errno_associated_const!(NOPROTOOPT, ENOPROTOOPT);
    errno_associated_const!(NOSPC, ENOSPC);
    errno_associated_const!(NOSR, ENOSR);
    errno_associated_const!(NOSTR, ENOSTR);
    errno_associated_const!(NOSYS, ENOSYS);
    errno_associated_const!(NOTBLK, ENOTBLK);
    errno_associated_const!(NOTCONN, ENOTCONN);
    errno_associated_const!(NOTDIR, ENOTDIR);
    errno_associated_const!(NOTEMPTY, ENOTEMPTY);
    errno_associated_const!(NOTNAM, ENOTNAM);
    errno_associated_const!(NOTRECOVERABLE, ENOTRECOVERABLE);
    errno_associated_const!(NOTSOCK, ENOTSOCK);
    errno_associated_const!(NOTTY, ENOTTY);
    errno_associated_const!(NOTUNIQ, ENOTUNIQ);
    errno_associated_const!(NXIO, ENXIO);
    errno_associated_const!(OPNOTSUPP, EOPNOTSUPP);
    errno_associated_const!(OVERFLOW, EOVERFLOW);
    errno_associated_const!(OWNERDEAD, EOWNERDEAD);
    errno_associated_const!(PERM, EPERM);
    errno_associated_const!(PFNOSUPPORT, EPFNOSUPPORT);
    errno_associated_const!(PIPE, EPIPE);
    errno_associated_const!(PROTO, EPROTO);
    errno_associated_const!(PROTONOSUPPORT, EPROTONOSUPPORT);
    errno_associated_const!(PROTOTYPE, EPROTOTYPE);
    errno_associated_const!(RANGE, ERANGE);
    errno_associated_const!(REMCHG, EREMCHG);
    errno_associated_const!(REMOTE, EREMOTE);
    errno_associated_const!(REMOTEIO, EREMOTEIO);
    errno_associated_const!(RESTART, ERESTART);
    errno_associated_const!(RFKILL, ERFKILL);
    errno_associated_const!(ROFS, EROFS);
    errno_associated_const!(SHUTDOWN, ESHUTDOWN);
    errno_associated_const!(SOCKTNOSUPPORT, ESOCKTNOSUPPORT);
    errno_associated_const!(SPIPE, ESPIPE);
    errno_associated_const!(SRCH, ESRCH);
    errno_associated_const!(SRMNT, ESRMNT);
    errno_associated_const!(STALE, ESTALE);
    errno_associated_const!(STRPIPE, ESTRPIPE);
    errno_associated_const!(TIME, ETIME);
    errno_associated_const!(TIMEDOUT, ETIMEDOUT);
    errno_associated_const!(TOOMANYREFS, ETOOMANYREFS);
    errno_associated_const!(TXTBSY, ETXTBSY);
    errno_associated_const!(UCLEAN, EUCLEAN);
    errno_associated_const!(UNATCH, EUNATCH);
    errno_associated_const!(USERS, EUSERS);
    errno_associated_const!(WOULDBLOCK, EWOULDBLOCK);
    errno_associated_const!(XDEV, EXDEV);
    errno_associated_const!(XFULL, EXFULL);
}

//FIXME: put these in their own file, fill them with the rest of the syscalls
//       for uniformity

/// Syscall constants on 64-bit width pointer architectures.
#[cfg(target_pointer_width = "64")]
mod abi {
    pub const NR_PPOLL: std::ffi::c_long =
        linux_raw_sys::general::__NR_ppoll as _;
    pub const NR_GETEUID: std::ffi::c_long =
        linux_raw_sys::general::__NR_geteuid as _;
    pub const NR_GETEGID: std::ffi::c_long =
        linux_raw_sys::general::__NR_getegid as _;
}

/// Syscall constants on 32-bit width pointer architectures.
#[cfg(target_pointer_width = "32")]
mod abi {
    pub const NR_PPOLL: std::ffi::c_long =
        linux_raw_sys::general::__NR_ppoll_time64 as _;
    pub const NR_GETEUID: std::ffi::c_long =
        linux_raw_sys::general::__NR_geteuid32 as _;
    pub const NR_GETEGID: std::ffi::c_long =
        linux_raw_sys::general::__NR_getegid32 as _;
}

/// User ID type used by the kernel.
pub type RawUid = linux::__kernel_uid_t;

/// Group ID type used by the kernel.
pub type RawGid = linux::__kernel_gid_t;

/// Process ID type used by the kernel.
pub type RawPid = linux::__kernel_pid_t;

/// Wrapper over a user ID.
///
/// This ID is guaranteed to not be `-1`.
#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub struct Uid(RawUid);

impl Uid {
    /// Access the raw user ID value.
    pub const fn as_raw(self) -> RawUid {
        self.0
    }

    /// Construct a user ID without checking for `-1`.
    ///
    /// # Safety
    ///
    /// This value must not be `-1`.
    pub const unsafe fn from_raw_unchecked(value: RawUid) -> Self {
        Self(value)
    }

    /// Construct a user ID, checking for `-1`.
    pub const fn from_raw(value: RawUid) -> Option<Self> {
        if value == RawUid::MAX {
            return None;
        }

        //SAFETY: we just checked that it wasn't `-1`.
        Some(unsafe { Self::from_raw_unchecked(value) })
    }
}

/// Wrapper over a group ID.
///
/// This ID is guaranteed to not be `-1`.
#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub struct Gid(RawGid);

impl Gid {
    /// Access the raw group ID value.
    pub const fn as_raw(self) -> RawGid {
        self.0
    }

    /// Construct a group ID without checking for `-1`.
    ///
    /// # Safety
    ///
    /// This value must not be `-1`.
    pub const unsafe fn from_raw_unchecked(value: RawGid) -> Self {
        Self(value)
    }

    /// Construct a group ID, checking for `-1`.
    pub const fn from_raw(value: RawGid) -> Option<Self> {
        if value == RawGid::MAX {
            return None;
        }

        //SAFETY: we just checked that it wasn't `-1`.
        Some(unsafe { Self::from_raw_unchecked(value) })
    }
}

/// Wrapper over a nonzero process ID.
#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash)]
pub struct Pid(NonZero<RawPid>);

impl Pid {
    /// Access the raw process ID value.
    pub const fn as_raw(self) -> RawPid {
        self.0.get()
    }

    /// Access the raw process ID value as a nonzero value.
    pub const fn as_raw_nonzero(self) -> NonZero<RawPid> {
        self.0
    }

    /// Construct a process ID without checking that it is nonzero.
    ///
    /// # Safety
    ///
    /// The value must not be zero.
    pub const unsafe fn from_raw_unchecked(value: RawPid) -> Self {
        //SAFETY: caller has asserted the correctness of this
        Self(unsafe { NonZero::<RawPid>::new_unchecked(value) })
    }

    /// Construct a process ID from a nonzero value.
    pub const fn from_raw_nonzero(value: NonZero<RawPid>) -> Self {
        Self(value)
    }

    /// Construct a process ID, checking that it is not zero.
    pub const fn from_raw(value: RawPid) -> Option<Self> {
        if let Some(value) = NonZero::<RawPid>::new(value) {
            Some(Self(value))
        } else {
            None
        }
    }
}

/// Typical [`WithCStr`] buffer length for single path components.
///
/// Currently uses [`linux::NAME_MAX`] plus one for the null byte. See
/// `limits.h(0p)` for more details.
pub const PATH_COMPONENT_MAX: usize = linux::NAME_MAX as usize + 1;

/// Typical [`WithCStr`] buffer length for whole paths.
///
/// Currently uses [`linux::PATH_MAX`]. See `limits.h(0p)` for more details.
pub const PATH_MAX: usize = linux::PATH_MAX as usize;

/// Wrapper for retrieving the last `errno(3)` value and converting it to
/// [`Errno`].
///
/// # Notes
///
/// Remove once libc has been torn from the library. Direct syscalls do not need
/// this.
pub fn last_errno() -> Errno {
    //SAFETY: part of the linux binary standard. see
    //        http://refspecs.linux-foundation.org/LSB_4.0.0/LSB-Core-generic/LSB-Core-generic/baselib---errno-location.html
    let errno_location = unsafe { libc::__errno_location() };

    //SAFETY: we're dereferencing a location that by the lsb, must exist
    Errno::from_raw_os_error(unsafe { *errno_location })
}

/// Helper macro for generating [`libc::syscall`] wrappers of fixed argument
/// counts.
macro_rules! fixed_syscall {
    ($name:ident(number $(, $arg:ident)*)) => {
        /// [`libc::syscall`] wrapper specialized to a set number of arguments.
        ///
        /// # Safety
        ///
        /// This is fundamentally unsafe. Make sure you've read the
        /// documentation for the syscall you're using.
        unsafe fn $name(
            number: ffi::c_long,
            $($arg: Arg),*
        ) -> Result<ffi::c_ulong, Errno> {
            //SAFETY: caller knows what they're doing
            let return_value = unsafe {
                ::libc::syscall(
                    number,
                    $($arg.into_raw()),*
                )
            };
            if return_value == -1 {
                return Err(last_errno());
            }

            Ok(return_value as ffi::c_ulong)
        }
    };
}

fixed_syscall!(syscall0(number));
fixed_syscall!(syscall1(number, arg1));
fixed_syscall!(syscall2(number, arg1, arg2));
fixed_syscall!(syscall3(number, arg1, arg2, arg3));
fixed_syscall!(syscall4(number, arg1, arg2, arg3, arg4));
fixed_syscall!(syscall5(number, arg1, arg2, arg3, arg4, arg5));
fixed_syscall!(syscall6(number, arg1, arg2, arg3, arg4, arg5, arg6));

/// [`linux::AT_FDCWD`].
#[derive(Copy, Clone, Debug)]
pub struct Cwd;

/// File descriptor wrapper for *at syscalls.
#[derive(Debug)]
pub struct AtFd<'fd> {
    inner: AtFdInner<'fd>,
}

/// Internal state of the file descriptor wrapper used for *at syscalls.
#[derive(Debug)]
enum AtFdInner<'fd> {
    /// Borrowed file descriptor.
    Borrowed(BorrowedFd<'fd>),

    /// Owned file descriptor.
    Owned(OwnedFd),

    /// [`linux::AT_FDCWD`].
    Cwd,
}

impl<'fd> From<&'fd Self> for AtFd<'fd> {
    fn from(fd: &'fd Self) -> Self {
        Self {
            inner: match &fd.inner {
                AtFdInner::Borrowed(fd) => AtFdInner::Borrowed(*fd),
                AtFdInner::Owned(fd) => AtFdInner::Borrowed(fd.as_fd()),
                AtFdInner::Cwd => AtFdInner::Cwd,
            },
        }
    }
}

impl<'fd, T> From<&'fd T> for AtFd<'fd>
where
    T: AsFd + ?Sized,
{
    fn from(fd: &'fd T) -> Self {
        Self {
            inner: AtFdInner::Borrowed(fd.as_fd()),
        }
    }
}

impl<'fd> From<BorrowedFd<'fd>> for AtFd<'fd> {
    fn from(fd: BorrowedFd<'fd>) -> Self {
        Self {
            inner: AtFdInner::Borrowed(fd),
        }
    }
}

impl<'fd> From<OwnedFd> for AtFd<'fd> {
    fn from(fd: OwnedFd) -> Self {
        Self {
            inner: AtFdInner::Owned(fd),
        }
    }
}

impl<'fd> From<Cwd> for AtFd<'fd> {
    fn from(_: Cwd) -> Self {
        Self {
            inner: AtFdInner::Cwd,
        }
    }
}

/// Representation of string types that may become a [`CStr`].
pub trait WithCStr {
    /// Converts this value into a [`CStr`] and calls the provided closure with
    /// the string.
    ///
    /// # Errors
    ///
    /// This method errors if the null byte check is not passed, if the buffer's
    /// length was not enough to contain the new [`CStr`], or if the provided
    /// closure errors.
    fn with_c_str<const N: usize, T, E>(
        &self,
        //TODO: allow the error of the [`Result`] to be any type which can be
        //      converted into `E` instead of requiring it to be `E` itself
        f: impl FnOnce(&CStr) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<ffi::FromBytesWithNulError> + From<CStrBufferTooSmall>;
}

impl WithCStr for &CStr {
    fn with_c_str<const N: usize, T, E>(
        &self,
        f: impl FnOnce(&CStr) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<ffi::FromBytesWithNulError> + From<CStrBufferTooSmall>,
    {
        f(self)
    }
}

impl WithCStr for &[u8] {
    fn with_c_str<const N: usize, T, E>(
        &self,
        f: impl FnOnce(&CStr) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<ffi::FromBytesWithNulError> + From<CStrBufferTooSmall>,
    {
        //TODO: we could use [`MaybeUninit`] here...
        let mut buffer = [0; N];

        (self.len() < buffer.len()).ok_or(CStrBufferTooSmall)?;

        //SAFETY: we established the length is within our bounds
        unsafe { buffer.get_unchecked_mut(..self.len()) }.copy_from_slice(self);

        //SAFETY: we established the length is within our bounds
        let c_str = CStr::from_bytes_with_nul(unsafe {
            buffer.get_unchecked(..self.len() + 1)
        })?;

        f(c_str)
    }
}

impl WithCStr for &OsStr {
    fn with_c_str<const N: usize, T, E>(
        &self,
        f: impl FnOnce(&CStr) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<ffi::FromBytesWithNulError> + From<CStrBufferTooSmall>,
    {
        self.as_bytes().with_c_str::<N, T, E>(f)
    }
}

impl WithCStr for &str {
    fn with_c_str<const N: usize, T, E>(
        &self,
        f: impl FnOnce(&CStr) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<ffi::FromBytesWithNulError> + From<CStrBufferTooSmall>,
    {
        self.as_bytes().with_c_str::<N, T, E>(f)
    }
}

/// Representation of a syscall argument used for conversions.
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
struct Arg(ffi::c_long);

impl Arg {
    /// Conversion to satisfy [`libc::syscall`]'s calling convention.
    fn into_raw(self) -> ffi::c_long {
        self.0
    }

    /// Construct a syscall argument from an immutable pointer value.
    fn from_ptr<T>(ptr: *const T) -> Self {
        Self(ptr as usize as ffi::c_long)
    }

    /// Construct a syscall argument from a mutable pointer value.
    fn from_mut_ptr<T>(ptr: *mut T) -> Self {
        Self(ptr as usize as ffi::c_long)
    }

    /// Construct a syscall argument from a C string.
    fn from_c_str(c_str: &'_ CStr) -> Self {
        Self::from_ptr(c_str.as_ptr())
    }

    /// Construct a syscall argument from a file descriptor.
    fn from_fd(fd: BorrowedFd<'_>) -> Self {
        Self(fd.as_fd().as_raw_fd() as ffi::c_long)
    }

    /// Construct a syscall argument from an [`AtFd`].
    ///
    /// We can't take it directly as that would drop the [`OwnedFd`] if it is.
    fn from_at_fd(fd: &AtFd<'_>) -> Self {
        match fd.inner {
            AtFdInner::Borrowed(fd) => Self::from_fd(fd.as_fd()),
            AtFdInner::Owned(ref fd) => Self::from_fd(fd.as_fd()),
            AtFdInner::Cwd => Self::from_int(linux::AT_FDCWD),
        }
    }

    /// Construct a syscall argument from an unsigned integer.
    fn from_uint(value: ffi::c_uint) -> Self {
        Self(value as ffi::c_long)
    }

    /// Construct a syscall argument from a signed integer.
    fn from_int(value: ffi::c_int) -> Self {
        Self(value as ffi::c_long)
    }

    /// Construct a syscall argument from an unsigned long.
    fn from_ulong(value: ffi::c_ulong) -> Self {
        Self(value as ffi::c_long)
    }

    /// Construct a syscall from a signed long.
    fn from_long(value: ffi::c_long) -> Self {
        Self(value)
    }

    /// Construct a syscall argument from a usize value.
    fn from_usize(value: usize) -> Self {
        Self(value as ffi::c_long)
    }

    /// Construct a syscall argument from a pid.
    fn from_pid(pid: Pid) -> Self {
        Self::from_int(pid.as_raw())
    }
}

/// `clone3(2)`.
///
/// # Safety
///
/// See the manpage, and the safety disclaimer on `Policy::clone_into`. There
/// are too many invariants to detail here right now.
pub unsafe fn clone3(
    args: impl Borrow<linux::clone_args>,
) -> Result<CloneResult, SyscallError> {
    //SAFETY: caller has agreed to not perform unsafe actions post-clone
    let who_am_i = unsafe {
        syscall2(
            linux::__NR_clone3 as ffi::c_long,
            Arg::from_ptr(args.borrow()),
            Arg::from_usize(size_of::<linux::clone_args>()),
        )
        .wrap_syscall(Syscall::Clone3)?
    };
    Ok(CloneResult::from(who_am_i))
}

/// Result of calling `clone3(2)`.
pub enum CloneResult {
    /// In the parent process, knowing the [`Pid`] of the child.
    Parent(Pid),

    /// In the child process.
    Child,
}

impl From<ffi::c_ulong> for CloneResult {
    fn from(value: ffi::c_ulong) -> Self {
        if value == 0 {
            return Self::Child;
        }

        //SAFETY: we checked it wasn't zero, and the documentation of
        //        `clone3(2)` indicates it must be a valid pid
        Self::Parent(unsafe { Pid::from_raw_unchecked(value as i32) })
    }
}

/// `mount_setattr(2)`
pub fn mount_setattr<'a>(
    dirfd: impl Into<AtFd<'a>>,
    path: &CStr,
    flags: ffi::c_uint,
    attr: impl Borrow<linux::mount_attr>,
) -> Result<(), SyscallError> {
    //SAFETY: incorrect flags have no bearing on the safety of this call.
    //        invariants upon the argument types (fd validity, reference
    //        validity) ensure memory safety
    let _ = unsafe {
        syscall5(
            linux::__NR_mount_setattr as ffi::c_long,
            Arg::from_at_fd(&dirfd.into()),
            Arg::from_c_str(path),
            Arg::from_uint(flags),
            Arg::from_ptr(attr.borrow()),
            Arg::from_usize(size_of::<linux::mount_attr>()),
        )
        .wrap_syscall(Syscall::MountSetattr)?
    };

    Ok(())
}

/// `dup3(2)`.
///
/// # Safety
///
/// The caller must ensure `newfd` does not conflict with an existing file
/// descriptor that is in use.
pub unsafe fn dup3(
    oldfd: impl AsFd,
    newfd: ffi::c_int,
    flags: ffi::c_int,
) -> Result<OwnedFd, SyscallError> {
    //SAFETY: caller has asserted `newfd` does not conflict with an existing
    //        file descriptor that is in use
    let newfd = unsafe {
        syscall3(
            linux::__NR_dup3 as ffi::c_long,
            Arg::from_fd(oldfd.as_fd()),
            Arg::from_int(newfd),
            Arg::from_int(flags),
        )
        .wrap_syscall(Syscall::Dup3)?
    };

    //SAFETY: `dup3(2)` asserts its return value is a valid fd on success
    Ok(unsafe { OwnedFd::from_raw_fd(newfd as ffi::c_int) })
}

/// `open_tree_attr(2)`.
pub fn open_tree_attr<'a>(
    dirfd: impl Into<AtFd<'a>>,
    path: &CStr,
    flags: ffi::c_uint,
    attr: impl Borrow<linux::mount_attr>,
) -> Result<OwnedFd, SyscallError> {
    //SAFETY: invariants on types passed to the function ensure that 1) `dirfd`
    //        is a valid file descriptor and that 2) `path` is a valid c string
    let raw_fd = unsafe {
        syscall5(
            linux::__NR_open_tree_attr as ffi::c_long,
            Arg::from_at_fd(&dirfd.into()),
            Arg::from_c_str(path),
            Arg::from_uint(flags),
            Arg::from_ptr(attr.borrow()),
            Arg::from_usize(size_of::<linux::mount_attr>()),
        )
        .wrap_syscall(Syscall::OpenTreeAttr)?
    };

    //SAFETY: `open_tree_attr(2)` asserts its return value is a valid fd on
    //        success
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd as ffi::c_int) })
}

/// `open_tree(2)`.
pub fn open_tree<'a>(
    dirfd: impl Into<AtFd<'a>>,
    path: &CStr,
    flags: ffi::c_uint,
) -> Result<OwnedFd, SyscallError> {
    //SAFETY: invariants on types passed to the function ensure that 1) `dirfd`
    //        is a valid file descriptor and that 2) `path` is a valid c string
    let raw_fd = unsafe {
        syscall3(
            linux::__NR_open_tree as ffi::c_long,
            Arg::from_at_fd(&dirfd.into()),
            Arg::from_c_str(path),
            Arg::from_uint(flags),
        )
        .wrap_syscall(Syscall::OpenTree)?
    };

    //SAFETY: `open_tree(2)` asserts its return value is a valid fd on success
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd as ffi::c_int) })
}

/// `pipe2(2)`.
pub fn pipe2(flags: ffi::c_int) -> Result<(OwnedFd, OwnedFd), SyscallError> {
    let mut fds: [ffi::c_int; 2] = [-1; 2];

    //SAFETY: we provide a valid memory location for it to write the fds to
    let _ = unsafe {
        syscall2(
            linux::__NR_pipe2 as ffi::c_long,
            Arg::from_mut_ptr(&mut fds),
            Arg::from_int(flags),
        )
        .wrap_syscall(Syscall::Pipe2)?
    };

    let [read_fd, write_fd] = fds;

    debug_assert_ne!(read_fd, -1, "the read fd must be valid");
    debug_assert_ne!(write_fd, -1, "the write fd must be valid");

    Ok((
        //SAFETY: on success, the read fd is initialized
        unsafe { OwnedFd::from_raw_fd(read_fd) },
        //SAFETY: on success, the write fd is initialized
        unsafe { OwnedFd::from_raw_fd(write_fd) },
    ))
}

/// `openat2(2)`.
pub fn openat2<'a>(
    dirfd: impl Into<AtFd<'a>>,
    path: &CStr,
    how: impl Borrow<linux::open_how>,
) -> Result<OwnedFd, SyscallError> {
    //SAFETY: invariants on the provided arguments ensure this call is valid
    let raw_fd = unsafe {
        syscall4(
            linux::__NR_openat2 as ffi::c_long,
            Arg::from_at_fd(&dirfd.into()),
            Arg::from_c_str(path),
            Arg::from_ptr(how.borrow()),
            Arg::from_usize(size_of::<linux::open_how>()),
        )
        .wrap_syscall(Syscall::Openat2)?
    };

    //SAFETY: on success, the fd is initialized
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd as ffi::c_int) })
}

/// `mkdirat(2)`.
pub fn mkdirat<'a>(
    dirfd: impl Into<AtFd<'a>>,
    path: &CStr,
    mode: ffi::c_uint,
) -> Result<(), SyscallError> {
    //SAFETY: invariants on the provided arguments ensure this call is valid
    let _ = unsafe {
        syscall3(
            linux::__NR_mkdirat as ffi::c_long,
            Arg::from_at_fd(&dirfd.into()),
            Arg::from_c_str(path),
            Arg::from_uint(mode),
        )
        .wrap_syscall(Syscall::Mkdirat)?
    };

    Ok(())
}

/// `umask(2)`.
pub fn umask(mode: ffi::c_uint) -> Result<ffi::c_uint, SyscallError> {
    //SAFETY: the provided arguments cannot result in a memory safety error
    let potential_umask = unsafe {
        syscall1(linux::__NR_umask as ffi::c_long, Arg::from_uint(mode))
            .wrap_syscall(Syscall::Umask)?
    };

    Ok(potential_umask as ffi::c_uint)
}

/// `statx(2)`.
pub fn statx<'a>(
    dirfd: impl Into<AtFd<'a>>,
    path: &CStr,
    flags: ffi::c_int,
    mask: ffi::c_uint,
) -> Result<linux::statx, SyscallError> {
    //SAFETY: this is a c structure which is valid when zero-initialized
    let mut statx = unsafe { mem::zeroed::<linux::statx>() };

    //SAFETY: invariants on the input types ensure this call is always safe to
    //        make
    let _ = unsafe {
        syscall5(
            linux::__NR_statx as ffi::c_long,
            Arg::from_at_fd(&dirfd.into()),
            Arg::from_c_str(path),
            Arg::from_int(flags),
            Arg::from_uint(mask),
            Arg::from_mut_ptr(&mut statx),
        )
        .wrap_syscall(Syscall::Statx)?
    };

    Ok(statx)
}

/// `fsopen(2)`.
pub fn fsopen(
    fsname: &CStr,
    flags: ffi::c_uint,
) -> Result<OwnedFd, SyscallError> {
    //SAFETY: invariants on `fsname` ensure it's a valid c string, invalid
    //        flags will not affect memory safety
    let raw_fd = unsafe {
        syscall2(
            linux::__NR_fsopen as ffi::c_long,
            Arg::from_c_str(fsname),
            Arg::from_uint(flags),
        )
        .wrap_syscall(Syscall::Fsopen)?
    };

    //SAFETY: on success, the fd is initialized
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd as ffi::c_int) })
}

/// `fsconfig(2)` with `FSCONFIG_SET_FLAG`.
pub fn fsconfig_set_flag(
    fd: impl AsFd,
    key: &CStr,
) -> Result<(), SyscallError> {
    //SAFETY: invariants on the types provided ensure this is a valid syscall
    let _ = unsafe {
        syscall5(
            linux::__NR_fsconfig as ffi::c_long,
            Arg::from_fd(fd.as_fd()),
            Arg::from_uint(fsconfig::FSCONFIG_SET_FLAG as ffi::c_uint),
            Arg::from_c_str(key),
            Arg::from_ptr(ptr::null::<ffi::c_void>()),
            Arg::from_int(0),
        )
        .wrap_syscall(Syscall::Fsconfig)?
    };

    Ok(())
}

/// `fsconfig(2)` with `FSCONFIG_SET_STRING`.
pub fn fsconfig_set_string(
    fd: impl AsFd,
    key: &CStr,
    value: &CStr,
) -> Result<(), SyscallError> {
    //SAFETY: invariants on the types provided ensure this is a valid syscall
    let _ = unsafe {
        syscall5(
            linux::__NR_fsconfig as ffi::c_long,
            Arg::from_fd(fd.as_fd()),
            Arg::from_uint(fsconfig::FSCONFIG_SET_STRING as ffi::c_uint),
            Arg::from_c_str(key),
            Arg::from_c_str(value),
            Arg::from_int(0),
        )
        .wrap_syscall(Syscall::Fsconfig)?
    };

    Ok(())
}

// /// `fsconfig(2)` with `FSCONFIG_SET_BINARY`.

/// `fsconfig(2)` with `FSCONFIG_SET_FD`.
pub fn fsconfig_set_fd(
    fd: impl AsFd,
    key: &CStr,
    aux: impl AsFd,
) -> Result<(), SyscallError> {
    //SAFETY: invariants on the provided types ensure this is a valid syscall
    let _ = unsafe {
        syscall5(
            linux::__NR_fsconfig as ffi::c_long,
            Arg::from_fd(fd.as_fd()),
            Arg::from_uint(fsconfig::FSCONFIG_SET_FD as ffi::c_uint),
            Arg::from_c_str(key),
            Arg::from_ptr(ptr::null::<ffi::c_void>()),
            Arg::from_fd(aux.as_fd()),
        )
        .wrap_syscall(Syscall::Fsconfig)?
    };

    Ok(())
}

// /// `fsconfig(2)` with `FSCONFIG_SET_PATH`.
// /// `fsconfig(2)` with `FSCONFIG_SET_PATH_EMPTY`.
// /// `fsconfig(2)` with `FSCONFIG_CMD_CREATE`.

/// `fsconfig(2)` with `FSCONFIG_CMD_CREATE_EXCL`.
pub fn fsconfig_cmd_create_excl(fd: impl AsFd) -> Result<(), SyscallError> {
    //SAFETY: invariants on the provided types ensure this is a valid syscall
    let _ = unsafe {
        syscall5(
            linux::__NR_fsconfig as ffi::c_long,
            Arg::from_fd(fd.as_fd()),
            Arg::from_uint(fsconfig::FSCONFIG_CMD_CREATE_EXCL as ffi::c_uint),
            Arg::from_ptr(ptr::null::<ffi::c_char>()),
            Arg::from_ptr(ptr::null::<ffi::c_void>()),
            Arg::from_int(0),
        )
        .wrap_syscall(Syscall::Fsconfig)?
    };

    Ok(())
}

// /// `fsconfig(2)` with `FSCONFIG_CMD_RECONFIGURE`.

/// `fsmount(2)`.
pub fn fsmount(
    fsfd: impl AsFd,
    flags: ffi::c_uint,
    attr_flags: ffi::c_uint,
) -> Result<OwnedFd, SyscallError> {
    //SAFETY: invariants on the provided types ensure this is a valid syscall
    let raw_fd = unsafe {
        syscall3(
            linux::__NR_fsmount as ffi::c_long,
            Arg::from_fd(fsfd.as_fd()),
            Arg::from_uint(flags),
            Arg::from_uint(attr_flags),
        )
        .wrap_syscall(Syscall::Fsmount)?
    };

    //SAFETY: if it succeeds, `fsmount(2)` is guaranteed to return a valid fd
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd as ffi::c_int) })
}

/// `move_mount(2)`.
pub fn move_mount<'from, 'to>(
    from_dirfd: impl Into<AtFd<'from>>,
    from_path: &CStr,
    to_dirfd: impl Into<AtFd<'to>>,
    to_path: &CStr,
    flags: ffi::c_uint,
) -> Result<(), SyscallError> {
    //SAFETY: invariants on the provided types ensure this is a valid syscall
    let _ = unsafe {
        syscall5(
            linux::__NR_move_mount as ffi::c_long,
            Arg::from_at_fd(&from_dirfd.into()),
            Arg::from_c_str(from_path),
            Arg::from_at_fd(&to_dirfd.into()),
            Arg::from_c_str(to_path),
            Arg::from_uint(flags),
        )
        .wrap_syscall(Syscall::MoveMount)?
    };

    Ok(())
}

/// `mount(2)`, specialized to change the propagation flags.
pub fn update_mount_propagation_flags(
    target: &CStr,
    mountflags: ffi::c_ulong,
) -> Result<(), SyscallError> {
    //SAFETY: invariants on the provided types ensure this is a valid syscall
    let _ = unsafe {
        syscall5(
            linux::__NR_mount as ffi::c_long,
            Arg::from_ptr(ptr::null::<ffi::c_char>()),
            Arg::from_c_str(target),
            Arg::from_ptr(ptr::null::<ffi::c_char>()),
            Arg::from_ulong(mountflags),
            Arg::from_ptr(ptr::null::<ffi::c_void>()),
        )
        .wrap_syscall(Syscall::Mount)?
    };

    Ok(())
}

/// `umount2(2)`.
pub fn umount2(target: &CStr, flags: ffi::c_int) -> Result<(), SyscallError> {
    //SAFETY: invariants on the provided types ensure this is a valid syscall
    let _ = unsafe {
        syscall2(
            linux::__NR_umount2 as ffi::c_long,
            Arg::from_c_str(target),
            Arg::from_int(flags),
        )
        .wrap_syscall(Syscall::Umount2)?
    };

    Ok(())
}

/// `write(2)`.
pub fn write(fd: impl AsFd, buffer: &[u8]) -> Result<usize, SyscallError> {
    //SAFETY: invariants on the provided types ensure this is a valid syscall
    let n_written = unsafe {
        syscall3(
            linux::__NR_write as ffi::c_long,
            Arg::from_fd(fd.as_fd()),
            Arg::from_ptr(buffer.as_ptr()),
            Arg::from_usize(buffer.len()),
        )
        .wrap_syscall(Syscall::Write)?
    };

    Ok(n_written as usize)
}

/// `read(2)`.
pub fn read(fd: impl AsFd, buffer: &mut [u8]) -> Result<usize, SyscallError> {
    let n_read = unsafe {
        syscall3(
            linux::__NR_read as ffi::c_long,
            Arg::from_fd(fd.as_fd()),
            Arg::from_mut_ptr(buffer.as_mut_ptr()),
            Arg::from_usize(buffer.len()),
        )
        .wrap_syscall(Syscall::Read)?
    };

    Ok(n_read as usize)
}

/// `close(2)`.
///
/// # Safety
///
/// It is the caller's responsibility to ensure that the specified file
/// descriptor is 1) open and 2) not expected to be open after calling
/// `close(2)`.
pub unsafe fn close(fd: impl IntoRawFd) {
    //NOTE: i debated whether or not to take [`IntoRawFd`] as it does not
    //      strictly require ownership transfer, but the only
    //      alternative---taking [`RawFd`]---does not either. this is marginally
    //      more ergonomic anyway

    //NOTE: we intentionally ignore the error because the potential errors are
    //      more hazardous to handle than they are to ignore
    //SAFETY: the caller asserts this file descriptor is not expected to be
    //         open after this call
    let _ = unsafe {
        syscall1(
            linux::__NR_close as ffi::c_long,
            Arg::from_int(fd.into_raw_fd()),
        )
    };
}

/// `eventfd2(2)`.
pub fn eventfd2(
    initval: ffi::c_uint,
    flags: ffi::c_int,
) -> Result<OwnedFd, SyscallError> {
    //SAFETY: there's no possible set of values here that would cause memory
    //        unsafety
    let raw_fd = unsafe {
        syscall2(
            linux::__NR_eventfd2 as ffi::c_long,
            Arg::from_uint(initval),
            Arg::from_int(flags),
        )
        .wrap_syscall(Syscall::Eventfd2)?
    };

    //SAFETY: `eventfd(2)` returns a valid fd on success
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd as ffi::c_int) })
}

/// Representation of a pollfd.
#[repr(transparent)]
#[derive(Debug)]
pub struct PollFd<'fd>(linux::pollfd, PhantomData<&'fd ()>);

impl<'fd> PollFd<'fd> {
    /// Create a new [`PollFd`] from the given [`BorrowedFd`].
    pub fn new(fd: BorrowedFd<'fd>, events: ffi::c_short) -> Self {
        Self(
            linux::pollfd {
                fd: fd.as_raw_fd(),
                events,
                revents: 0,
            },
            PhantomData,
        )
    }

    /// Get the returned events set by the kernel.
    pub fn revents(&self) -> ffi::c_short {
        self.0.revents
    }

    /// Clear the revents set by the kernel.
    pub fn clear_revents(&mut self) {
        self.0.revents = 0;
    }
}

/// `ppoll(2)`.
//TODO: check for 32-bit behavior???
pub fn ppoll(
    fds: &mut [PollFd<'_>],
    mut timeout: Option<linux::__kernel_timespec>,
) -> Result<usize, SyscallError> {
    let timespec = if let Some(timeout) = &mut timeout {
        timeout
    } else {
        ptr::null_mut::<linux::__kernel_timespec>()
    };

    //SAFETY: the invariants on all input types guarantee the safety of this
    let n_updated = unsafe {
        syscall5(
            abi::NR_PPOLL,
            Arg::from_mut_ptr(fds.as_mut_ptr()),
            Arg::from_usize(fds.len()),
            Arg::from_mut_ptr(timespec),
            Arg::from_ptr(ptr::null::<linux::sigset_t>()),
            Arg::from_usize(size_of::<linux::sigset_t>()),
        )
        .wrap_syscall(Syscall::Ppoll)?
    };

    Ok(n_updated as usize)
}

/// `sethostname(2)`.
pub fn sethostname(name: &[u8]) -> Result<(), SyscallError> {
    //SAFETY: the invariants on all input types guarantee the safety of this
    let _ = unsafe {
        syscall2(
            linux::__NR_sethostname as ffi::c_long,
            Arg::from_ptr(name.as_ptr()),
            Arg::from_usize(name.len()),
        )
        .wrap_syscall(Syscall::Sethostname)?
    };

    Ok(())
}

/// `setdomainname(2)`.
pub fn setdomainname(name: &[u8]) -> Result<(), SyscallError> {
    //SAFETY: the invariants on all input types guarantee the safety of this
    let _ = unsafe {
        syscall2(
            linux::__NR_setdomainname as ffi::c_long,
            Arg::from_ptr(name.as_ptr()),
            Arg::from_usize(name.len()),
        )
        .wrap_syscall(Syscall::Setdomainname)?
    };

    Ok(())
}

/// `prctl(2)` with `PR_CAP_AMBIENT_RAISE(2const)`.
///
/// `cap` must be a capability value equal to one of the `CAP_` constants.
pub fn raise_capability_into_ambient_set(
    cap: ffi::c_long,
) -> Result<(), SyscallError> {
    //SAFETY: there's not really an unsafe way to call this
    let _ = unsafe {
        syscall5(
            linux::__NR_prctl as ffi::c_long,
            Arg::from_long(prctl::PR_CAP_AMBIENT as _),
            Arg::from_long(prctl::PR_CAP_AMBIENT_RAISE as _),
            Arg::from_long(cap),
            Arg::from_long(0),
            Arg::from_long(0),
        )
        .wrap_syscall(Syscall::Prctl)?
    };

    Ok(())
}

/// `prctl(2)` with `PR_CAPBSET_DROP(2const)`.
///
/// `cap` must be a capability value equal to one of the `CAP_` constants.
pub fn drop_capability_from_bounding_set(
    cap: ffi::c_long,
) -> Result<(), SyscallError> {
    //SAFETY: there's not really an unsafe way to call this
    let _ = unsafe {
        syscall5(
            linux::__NR_prctl as ffi::c_long,
            Arg::from_long(prctl::PR_CAPBSET_DROP as _),
            Arg::from_long(cap),
            Arg::from_long(0),
            Arg::from_long(0),
            Arg::from_long(0),
        )
        .wrap_syscall(Syscall::Prctl)?
    };

    Ok(())
}

/// Wrapper for [`linux::cap_user_data_t`] to be used with [`capset`].
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CapabilitySets {
    pub effective: CapabilitySet,
    pub permitted: CapabilitySet,
    pub inheritable: CapabilitySet,
}

impl CapabilitySets {
    fn into_user_cap_data_struct(self) -> [linux::__user_cap_data_struct; 2] {
        [
            linux::__user_cap_data_struct {
                effective: self.effective.bits() as u32,
                permitted: self.permitted.bits() as u32,
                inheritable: self.inheritable.bits() as u32,
            },
            linux::__user_cap_data_struct {
                effective: (self.effective.bits() >> 32) as u32,
                permitted: (self.permitted.bits() >> 32) as u32,
                inheritable: (self.inheritable.bits() >> 32) as u32,
            },
        ]
    }
}

/// `capset(2)`.
pub fn set_capabilities(data: CapabilitySets) -> Result<(), SyscallError> {
    let data = data.into_user_cap_data_struct();
    let hdr = linux::__user_cap_header_struct {
        version: linux::_LINUX_CAPABILITY_VERSION_3,
        //NOTE: this can only differ from nonzero or the current tid on really
        //      ancient kernels that rust doesn't support
        pid: 0,
    };

    //SAFETY: everything provided is structurally unable to be invalid
    let _ = unsafe {
        syscall2(
            linux::__NR_capset as ffi::c_long,
            Arg::from_ptr(&hdr),
            Arg::from_ptr(data.as_ptr()),
        )
        .wrap_syscall(Syscall::Capset)?
    };

    Ok(())
}

/// `prctl(2)` with `PR_SET_NO_NEW_PRIVS(2const)`.
pub fn set_no_new_privs() -> Result<(), SyscallError> {
    //SAFETY: all parameters are constant and structurally correct
    let _ = unsafe {
        syscall5(
            linux::__NR_prctl as ffi::c_long,
            Arg::from_long(prctl::PR_SET_NO_NEW_PRIVS as _),
            Arg::from_long(1),
            Arg::from_long(0),
            Arg::from_long(0),
            Arg::from_long(0),
        )
        .wrap_syscall(Syscall::Prctl)?
    };

    Ok(())
}

/// `setns(2)`.
pub fn setns(fd: impl AsFd, nstype: ffi::c_int) -> Result<(), SyscallError> {
    //SAFETY: safety is ensured by the types of the arguments provided
    //
    //        this syscall does not allow unsharing the file descriptor table,
    //        so there are no safety hazards posed by it
    let _ = unsafe {
        syscall2(
            linux::__NR_setns as ffi::c_long,
            Arg::from_fd(fd.as_fd()),
            Arg::from_int(nstype),
        )
        .wrap_syscall(Syscall::Setns)?
    };

    Ok(())
}

/// `unshare(2)`.
///
/// # Safety
///
/// If using [`linux::CLONE_FILES`], the caller must ensure that this thread
/// does not attempt to use file descriptors from other threads.
pub unsafe fn unshare(flags: ffi::c_int) -> Result<(), SyscallError> {
    //SAFETY: the caller asserts that if they are using `CLONE_FILES` that this
    //        thread will not attempt to use file descriptors from other threads
    let _ = unsafe {
        syscall1(linux::__NR_unshare as ffi::c_long, Arg::from_int(flags))
            .wrap_syscall(Syscall::Unshare)?
    };

    Ok(())
}

/// `chdir(2)`.
pub fn chdir(path: &CStr) -> Result<(), SyscallError> {
    //SAFETY: the type of the argument ensures this call is safe
    let _ = unsafe {
        syscall1(linux::__NR_chdir as ffi::c_long, Arg::from_c_str(path))
            .wrap_syscall(Syscall::Chdir)?
    };

    Ok(())
}

/// `fchdir(2)`.
pub fn fchdir(fd: impl AsFd) -> Result<(), SyscallError> {
    //SAFETY: the type of the argument ensures this call is safe
    let _ = unsafe {
        syscall1(linux::__NR_fchdir as ffi::c_long, Arg::from_fd(fd.as_fd()))
            .wrap_syscall(Syscall::Fchdir)?
    };

    Ok(())
}

/// `chroot(2)`.
pub fn chroot(path: &CStr) -> Result<(), SyscallError> {
    //SAFETY: the type of the argument ensures this call is safe
    let _ = unsafe {
        syscall1(linux::__NR_chroot as ffi::c_long, Arg::from_c_str(path))
            .wrap_syscall(Syscall::Chroot)?
    };

    Ok(())
}

/// `getegid(2)`.
pub fn getegid() -> Result<Gid, SyscallError> {
    //SAFETY: there are no arguments to pass from the user
    let raw_gid =
        unsafe { syscall0(abi::NR_GETEGID).wrap_syscall(Syscall::Getegid)? };

    //SAFETY: this syscall won't return the maximum value
    Ok(unsafe { Gid::from_raw_unchecked(raw_gid as _) })
}

/// `geteuid(2)`.
pub fn geteuid() -> Result<Uid, SyscallError> {
    //SAFETY: there are no arguments to pass from the user
    let raw_uid =
        unsafe { syscall0(abi::NR_GETEUID).wrap_syscall(Syscall::Geteuid)? };

    //SAFETY: this syscall won't return the maximum value
    Ok(unsafe { Uid::from_raw_unchecked(raw_uid as _) })
}

/// `getpid(2)`.
pub fn getpid() -> Result<Pid, SyscallError> {
    //SAFETY: there are no arguments to pass from the user
    let raw_pid = unsafe {
        syscall0(linux::__NR_getpid as ffi::c_long)
            .wrap_syscall(Syscall::Getpid)?
    };

    //SAFETY: `getpid(2)` returns a valid pid
    Ok(unsafe { Pid::from_raw_unchecked(raw_pid as _) })
}

/// `pidfd_open(2)`.
pub fn pidfd_open(
    pid: Pid,
    flags: ffi::c_uint,
) -> Result<OwnedFd, SyscallError> {
    //SAFETY: invariants upon the types ensure the call is valid
    let raw_fd = unsafe {
        syscall2(
            linux::__NR_pidfd_open as ffi::c_long,
            Arg::from_pid(pid),
            Arg::from_uint(flags),
        )
        .wrap_syscall(Syscall::PidfdOpen)?
    };

    //SAFETY: `pidfd_open(2)` always returns a valid fd if it succeeds
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd as _) })
}

/// `pidfd_send_signal(2)` without `siginfo_t`.
pub fn pidfd_send_signal(
    pidfd: impl AsFd,
    sig: ffi::c_int,
    flags: ffi::c_uint,
) -> Result<(), SyscallError> {
    //FIXME: accept a wrapper over `siginfo_t`, but not the raw type because
    //       it's not very nice to work with

    //SAFETY: the invariants of the types provided ensure this is safe
    let _ = unsafe {
        syscall4(
            linux::__NR_pidfd_send_signal as ffi::c_long,
            Arg::from_fd(pidfd.as_fd()),
            Arg::from_int(sig),
            Arg::from_ptr(ptr::null::<linux::siginfo_t>()),
            Arg::from_uint(flags),
        )
        .wrap_syscall(Syscall::PidfdSendSignal)?
    };

    Ok(())
}

/// `prctl(2)` with `PR_SET_PDEATHSIG(2const)`.
///
/// Provide zero as the signal to clear the death signal.
pub fn set_parent_process_death_signal(
    sig: ffi::c_int,
) -> Result<(), SyscallError> {
    //SAFETY: all parameters are constant and structurally correct
    let _ = unsafe {
        syscall5(
            linux::__NR_prctl as ffi::c_long,
            Arg::from_long(prctl::PR_SET_PDEATHSIG as _),
            Arg::from_int(sig),
            Arg::from_long(0),
            Arg::from_long(0),
            Arg::from_long(0),
        )
        .wrap_syscall(Syscall::Prctl)?
    };

    Ok(())
}

/// `setsid(2)`.
pub fn setsid() -> Result<Pid, SyscallError> {
    //SAFETY: the caller passes no arguments to this function and this syscall
    //        cannot do anything that would cause memory unsafety
    let raw_pid = unsafe {
        syscall0(linux::__NR_setsid as ffi::c_long)
            .wrap_syscall(Syscall::Setsid)?
    };

    //SAFETY: `setsid(2)` always returns a valid pid
    Ok(unsafe { Pid::from_raw_unchecked(raw_pid as _) })
}

/// The target of a `waitid(2)` call.
#[derive(Debug)]
pub enum WaitFor<'fd> {
    /// Child with the specified pid.
    Pid(Pid),

    /// Child referred to by the pidfd.
    PidFd(BorrowedFd<'fd>),

    /// Any child with the specified process group id.
    ///
    /// If not provided wait for any child in the caller's process group.
    Pgid(Option<Pid>),

    /// Any child.
    All,
}

/// Wrapper for [`linux::siginfo_t`] when returned from a `waitid(2)` call.
#[derive(Copy, Clone)]
pub struct WaitIdStatus(linux::siginfo_t);

/// `waitid(2)`.
pub fn waitid(
    target: WaitFor<'_>,
    options: ffi::c_int,
) -> Result<Option<WaitIdStatus>, SyscallError> {
    //TODO: consider supporting rusage. may need abi-dependent work---check

    //SAFETY: this is a c structure which is valid when initialized to zero.
    //        we also need this to distinguish the state w/ `WNOHANG` specified
    let mut info = unsafe { mem::zeroed::<linux::siginfo_t>() };

    let _ = match target {
        WaitFor::Pid(pid) => {
            //SAFETY: the types of arguments provided ensure the safety of this
            //        call
            unsafe {
                syscall5(
                    linux::__NR_waitid as ffi::c_long,
                    //NOTE: not really sure what to use here but a ulong will
                    //      be at least a u32, which is the indicated type of
                    //      `P_PID`
                    Arg::from_ulong(linux::P_PID as _),
                    Arg::from_pid(pid),
                    Arg::from_mut_ptr(&mut info),
                    Arg::from_int(options),
                    Arg::from_ptr(ptr::null::<linux::rusage>()),
                )
            }
        }
        WaitFor::PidFd(fd) => {
            //SAFETY: the types of arguments provided ensure the safety of this
            //        call
            unsafe {
                syscall5(
                    linux::__NR_waitid as ffi::c_long,
                    Arg::from_ulong(linux::P_PIDFD as _),
                    Arg::from_fd(fd),
                    Arg::from_mut_ptr(&mut info),
                    Arg::from_int(options),
                    Arg::from_ptr(ptr::null::<linux::rusage>()),
                )
            }
        }
        WaitFor::Pgid(Some(pgid)) => {
            //SAFETY: the types of arguments provided ensure the safety of this
            //        call
            unsafe {
                syscall5(
                    linux::__NR_waitid as ffi::c_long,
                    Arg::from_ulong(linux::P_PGID as _),
                    Arg::from_pid(pgid),
                    Arg::from_mut_ptr(&mut info),
                    Arg::from_int(options),
                    Arg::from_ptr(ptr::null::<linux::rusage>()),
                )
            }
        }
        WaitFor::Pgid(None) => {
            //SAFETY: the types of arguments provided ensure the safety of this
            //        call
            unsafe {
                syscall5(
                    linux::__NR_waitid as ffi::c_long,
                    Arg::from_ulong(linux::P_PGID as _),
                    Arg::from_int(0),
                    Arg::from_mut_ptr(&mut info),
                    Arg::from_int(options),
                    Arg::from_ptr(ptr::null::<linux::rusage>()),
                )
            }
        }
        WaitFor::All => {
            //SAFETY: the types of arguments provided ensure the safety of this
            //        call
            unsafe {
                syscall5(
                    linux::__NR_waitid as ffi::c_long,
                    Arg::from_ulong(linux::P_ALL as _),
                    Arg::from_int(0),
                    Arg::from_mut_ptr(&mut info),
                    Arg::from_int(options),
                    Arg::from_ptr(ptr::null::<linux::rusage>()),
                )
            }
        }
    }
    .wrap_syscall(Syscall::Waitid)?;

    //SAFETY: these have been initialized correctly earlier as zero
    //        initialization is valid
    if unsafe {
        info.__bindgen_anon_1
            .__bindgen_anon_1
            ._sifields
            ._sigchld
            ._pid
    } == 0
    {
        Ok(None)
    } else {
        Ok(Some(WaitIdStatus(info)))
    }
}

/// `ioctl(2)` on a network device fd, with `SIOCGIFINDEX`.
pub fn interface_name_to_index(
    fd: impl AsFd,
    ifr_name: &CStr,
) -> Result<ffi::c_uint, SyscallError> {
    //SAFETY: this is a c structure which is valid when zeroed
    let mut ifreq = unsafe { mem::zeroed::<linux_net::ifreq>() };

    let ifname = ifr_name.to_bytes_with_nul();
    if let Some(target_ifname) =
        //SAFETY: we zero-initialized this structure so this is fine
        unsafe { &mut ifreq.ifr_ifrn.ifrn_name }.get_mut(..ifname.len())
    {
        bytemuck::cast_slice_mut(target_ifname).copy_from_slice(ifname);
    } else {
        return Err(SyscallError {
            syscall: Syscall::Ioctl,
            error: Errno::INVAL,
        });
    }

    //SAFETY: all arguments are guaranteed to be valid
    let _ = unsafe {
        syscall3(
            linux::__NR_ioctl as ffi::c_long,
            Arg::from_fd(fd.as_fd()),
            Arg::from_ulong(ioctl::SIOCGIFINDEX as _),
            Arg::from_mut_ptr(&mut ifreq),
        )
        .wrap_syscall(Syscall::Ioctl)?
    };

    //SAFETY: after the ioctl, this field is initialized to the index
    Ok(unsafe { ifreq.ifr_ifru.ifru_ivalue } as _)
}

/// `socket(2)`.
pub fn socket(
    domain: ffi::c_int,
    kind: ffi::c_int,
    protocol: ffi::c_int,
) -> Result<OwnedFd, SyscallError> {
    //SAFETY: there's no combination of arguments that would violate memory
    //        safety here
    let raw_fd = unsafe {
        syscall3(
            linux::__NR_socket as ffi::c_long,
            Arg::from_int(domain),
            Arg::from_int(kind),
            Arg::from_int(protocol),
        )
        .wrap_syscall(Syscall::Socket)?
    };

    //SAFETY: `socket(2)` returns a valid file descriptor on success
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd as _) })
}

/// `recvfrom(2)` without the source address fields.
//TODO: consider adding source address results somewhere. we don't really care
//      about it for our purposes so i'll ignore it for now
pub fn recvfrom(
    sockfd: impl AsFd,
    buffer: &mut [u8],
    flags: ffi::c_int,
) -> Result<usize, SyscallError> {
    //SAFETY: the invariants of the provided types ensure this call is safe
    let n_read = unsafe {
        syscall6(
            linux::__NR_recvfrom as ffi::c_long,
            Arg::from_fd(sockfd.as_fd()),
            Arg::from_mut_ptr(buffer.as_mut_ptr()),
            Arg::from_usize(buffer.len()),
            Arg::from_int(flags),
            Arg::from_mut_ptr(ptr::null_mut::<linux_net::sockaddr>()),
            Arg::from_mut_ptr(ptr::null_mut::<linux_net::socklen_t>()),
        )
        .wrap_syscall(Syscall::Recvfrom)?
    };

    Ok(n_read as _)
}

/// `sendto(2)` specialized for sending a netlink message to the kernel.
pub fn sendto_nl_kernel(
    sockfd: impl AsFd,
    buffer: &[u8],
    flags: ffi::c_int,
) -> Result<usize, SyscallError> {
    //FIXME: write a proper sendto wrapper. for now, because i don't want to
    //       deal with sockaddrs, i'm not going to do this
    //
    //       could have constructors that cast to sockaddr then do sizeof etc i
    //       think

    const SOCKADDR: netlink::sockaddr_nl = netlink::sockaddr_nl {
        nl_family: linux_net::AF_NETLINK as u16,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: 0,
    };

    //SAFETY: the invariants of the provided types ensure this call is safe
    let n_sent = unsafe {
        syscall6(
            linux::__NR_sendto as ffi::c_long,
            Arg::from_fd(sockfd.as_fd()),
            Arg::from_ptr(buffer.as_ptr()),
            Arg::from_usize(buffer.len()),
            Arg::from_int(flags),
            Arg::from_ptr(&SOCKADDR),
            Arg::from_usize(size_of::<netlink::sockaddr_nl>()),
        )
        .wrap_syscall(Syscall::Sendto)?
    };

    Ok(n_sent as _)
}

/// `exit(2)`.
pub fn exit(status: ffi::c_int) -> ! {
    let _ = unsafe {
        syscall1(linux::__NR_exit_group as ffi::c_long, Arg::from_int(status))
    };
    let _ = unsafe {
        syscall1(linux::__NR_exit as ffi::c_long, Arg::from_int(status))
    };

    //NOTE: there is really no point to doing anything else here. the safest
    //      thing to do is just do a spin loop
    loop {
        hint::spin_loop()
    }
}
