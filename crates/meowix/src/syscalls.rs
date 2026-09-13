// SPDX-License-Identifier: AGPL-3.0-only

//! Direct syscall wrappers.

use core::{
    borrow::{Borrow, BorrowMut},
    ffi::{self, CStr},
    hint,
    marker::PhantomData,
    mem::{self, MaybeUninit},
    ptr,
};
use linux_raw_sys::{
    general::{self as linux, fsconfig_command as fsconfig},
    ioctl, net as linux_net, netlink, prctl,
};

use crate::{
    abi,
    capabilities::CapabilitySets,
    errno::Errno,
    errors::{ResultErrnoExt, Syscall, SyscallError},
    fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd},
    ids::{Gid, Pid, Uid},
    syscall::*,
    util::AtFd,
};

/// Set the close-on-exec flag on syscalls instead of closing them.
pub const CLOSE_RANGE_CLOEXEC: ffi::c_int = 1 << 2;

/// When this flag is set, `open_tree(2)` returns a file descriptor
/// referring to a mount namespace with the copied mount tree mounted on top
/// of the real rootfs.
///
/// See [LWN] for more details.
///
/// [LWN]: https://lwn.net/Articles/1052262/
pub const OPEN_TREE_NAMESPACE: u32 = 1 << 1;

/// When this flag is set, auto-reap the child on exit.
///
/// See [the Linux kernel mailing list] and [LWN] for more details.
///
/// [the Linux kernel mailing list]: https://lkml.org/lkml/2026/2/23/580
/// [LWN]: https://lwn.net/Articles/1059673/
pub const CLONE_AUTOREAP: u64 = 1u64 << 34;

/// When this flag is set, spawn the child with the no new privileges prctl set.
pub const CLONE_NNP: u64 = 1u64 << 35;

/// When this flag is set, tie the child process' lifetime to the pidfd returned
/// by [`linux::CLONE_PIDFD`].
///
/// See [the Linux kernel mailing list] and [LWN] for more details.
///
/// [the Linux kernel mailing list]: https://lkml.org/lkml/2026/2/23/583
/// [LWN]: https://lwn.net/Articles/1059673/
pub const CLONE_PIDFD_AUTOKILL: u64 = 1u64 << 36;

/// `ioctl(2)` to retrieve information about a pidfd.
///
/// See [LWN] for more details.
///
/// [LWN]: https://lwn.net/Articles/992991/
const PIDFD_GET_INFO_V0: usize = 0xc040_ff0b;

/// Mask for [`PIDFD_GET_INFO_V0`] (and later revisions) to request the exit
/// code of the process.
const PIDFD_INFO_EXIT: u64 = 1 << 3;

/// Initial revision of the structure used by `PIDFD_GET_INFO`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct PidfdInfoV0 {
    /// Mask of fields set by the kernel.
    pub mask: u64,

    /// `cgroups(7)` id of the process.
    ///
    /// Always returned if available.
    pub cgroupid: u64,

    /// [`Pid`] of the process.
    ///
    /// Always returned.
    pub pid: u32,

    /// Thread group ID of the process.
    ///
    /// Always returned.
    pub tgid: u32,

    /// Parent process ID of the process.
    ///
    /// Always returned.
    pub ppid: u32,

    /// Real user ID of the process.
    ///
    /// Always returned.
    pub ruid: u32,

    /// Real group ID of the process.
    ///
    /// Always returned.
    pub rgid: u32,

    /// Effective user ID of the process.
    ///
    /// Always returned.
    pub euid: u32,

    /// Effective group ID of the process.
    ///
    /// Always returned.
    pub egid: u32,

    /// Saved user ID of the process.
    ///
    /// Always returned.
    pub suid: u32,

    /// Saved group ID of the process.
    ///
    /// Always returned.
    pub sgid: u32,

    /// Filesystem user ID of the process.
    ///
    /// Always returned.
    pub fsuid: u32,

    /// Filesystem group ID of the process.
    ///
    /// Always returned.
    pub fsgid: u32,

    /// Exit code of the process.
    ///
    /// Request with `PIDFD_INFO_EXIT`.
    pub exit_code: i32,
}

const _: () = {
    //NOTE: ensure that the struct is accurate
    assert!(size_of::<PidfdInfoV0>() == 64);
};

/// `clone3(2)`.
///
/// # Safety
///
/// Refer to the manpage for information on the potential hazards with making
/// this syscall. There is too much to detail here.
#[inline]
pub unsafe fn clone3(
    args: impl Borrow<linux::clone_args>,
) -> Result<CloneResult, SyscallError> {
    //SAFETY: caller has agreed to not perform unsafe actions post-clone
    let who_am_i = unsafe {
        syscall2(
            abi::CLONE3,
            Arg::from_ptr(args.borrow()),
            Arg::from_usize(size_of::<linux::clone_args>()),
        )
        .wrap_syscall(Syscall::Clone3)?
    } as i32;

    Ok(if who_am_i == 0 {
        CloneResult::Child
    } else {
        //SAFETY: we checked it wasn't zero after narrowing, and the
        //        documentation of `clone3(2)` specifies that it is a valid pid
        CloneResult::Parent(unsafe { Pid::from_raw_unchecked(who_am_i) })
    })
}

/// Result of calling `clone3(2)`.
#[derive(Copy, Clone, Debug)]
pub enum CloneResult {
    /// In the parent process, knowing the [`Pid`] of the child.
    Parent(Pid),

    /// In the child process.
    Child,
}

/// `mount_setattr(2)`
#[inline]
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
            abi::MOUNT_SETATTR,
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
#[inline]
pub unsafe fn dup3(
    oldfd: impl AsFd,
    newfd: ffi::c_int,
    flags: ffi::c_int,
) -> Result<OwnedFd, SyscallError> {
    //SAFETY: caller has asserted `newfd` does not conflict with an existing
    //        file descriptor that is in use
    let newfd = unsafe {
        syscall3(
            abi::DUP3,
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
#[inline]
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
            abi::OPEN_TREE_ATTR,
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
#[inline]
pub fn open_tree<'a>(
    dirfd: impl Into<AtFd<'a>>,
    path: &CStr,
    flags: ffi::c_uint,
) -> Result<OwnedFd, SyscallError> {
    //SAFETY: invariants on types passed to the function ensure that 1) `dirfd`
    //        is a valid file descriptor and that 2) `path` is a valid c string
    let raw_fd = unsafe {
        syscall3(
            abi::OPEN_TREE,
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
#[inline]
pub fn pipe2(flags: ffi::c_int) -> Result<(OwnedFd, OwnedFd), SyscallError> {
    let mut fds: [ffi::c_int; 2] = [-1; 2];

    //SAFETY: we provide a valid memory location for it to write the fds to
    let _ = unsafe {
        syscall2(
            abi::PIPE2,
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
#[inline]
pub fn openat2<'a>(
    dirfd: impl Into<AtFd<'a>>,
    path: &CStr,
    how: impl Borrow<linux::open_how>,
) -> Result<OwnedFd, SyscallError> {
    //SAFETY: invariants on the provided arguments ensure this call is valid
    let raw_fd = unsafe {
        syscall4(
            abi::OPENAT2,
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
#[inline]
pub fn mkdirat<'a>(
    dirfd: impl Into<AtFd<'a>>,
    path: &CStr,
    mode: ffi::c_uint,
) -> Result<(), SyscallError> {
    //SAFETY: invariants on the provided arguments ensure this call is valid
    let _ = unsafe {
        syscall3(
            abi::MKDIRAT,
            Arg::from_at_fd(&dirfd.into()),
            Arg::from_c_str(path),
            Arg::from_uint(mode),
        )
        .wrap_syscall(Syscall::Mkdirat)?
    };

    Ok(())
}

/// `umask(2)`.
#[inline]
pub fn umask(mode: ffi::c_uint) -> Result<ffi::c_uint, SyscallError> {
    //SAFETY: the provided arguments cannot result in a memory safety error
    let potential_umask = unsafe {
        syscall1(abi::UMASK, Arg::from_uint(mode))
            .wrap_syscall(Syscall::Umask)?
    };

    Ok(potential_umask as ffi::c_uint)
}

/// `statx(2)`.
#[inline]
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
            abi::STATX,
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
#[inline]
pub fn fsopen(
    fsname: &CStr,
    flags: ffi::c_uint,
) -> Result<OwnedFd, SyscallError> {
    //SAFETY: invariants on `fsname` ensure it's a valid c string, invalid
    //        flags will not affect memory safety
    let raw_fd = unsafe {
        syscall2(abi::FSOPEN, Arg::from_c_str(fsname), Arg::from_uint(flags))
            .wrap_syscall(Syscall::Fsopen)?
    };

    //SAFETY: on success, the fd is initialized
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd as ffi::c_int) })
}

/// `fsconfig(2)` with `FSCONFIG_SET_FLAG`.
#[inline]
pub fn fsconfig_set_flag(
    fd: impl AsFd,
    key: &CStr,
) -> Result<(), SyscallError> {
    //SAFETY: invariants on the types provided ensure this is a valid syscall
    let _ = unsafe {
        syscall5(
            abi::FSCONFIG,
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
#[inline]
pub fn fsconfig_set_string(
    fd: impl AsFd,
    key: &CStr,
    value: &CStr,
) -> Result<(), SyscallError> {
    //SAFETY: invariants on the types provided ensure this is a valid syscall
    let _ = unsafe {
        syscall5(
            abi::FSCONFIG,
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

/// `fsconfig(2)` with `FSCONFIG_SET_FD`.
#[inline]
pub fn fsconfig_set_fd(
    fd: impl AsFd,
    key: &CStr,
    aux: impl AsFd,
) -> Result<(), SyscallError> {
    //SAFETY: invariants on the provided types ensure this is a valid syscall
    let _ = unsafe {
        syscall5(
            abi::FSCONFIG,
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

/// `fsconfig(2)` with `FSCONFIG_CMD_CREATE`.
///
/// # Warning
///
/// Prefer [`fsconfig_cmd_create_excl`] wherever possible as it avoids reusing
/// extant filesystem instances. For more information, see its documentation and
/// `fsconfig(2)`.
#[inline]
pub fn fsconfig_cmd_create(fd: impl AsFd) -> Result<(), SyscallError> {
    //SAFETY: invariants upon the provided types ensure this is a valid syscall
    let _ = unsafe {
        syscall5(
            abi::FSCONFIG,
            Arg::from_fd(fd.as_fd()),
            Arg::from_uint(fsconfig::FSCONFIG_CMD_CREATE as ffi::c_uint),
            Arg::from_ptr(ptr::null::<ffi::c_char>()),
            Arg::from_ptr(ptr::null::<ffi::c_void>()),
            Arg::from_int(0),
        )
        .wrap_syscall(Syscall::Fsconfig)?
    };

    Ok(())
}

/// `fsconfig(2)` with `FSCONFIG_CMD_CREATE_EXCL`.
#[inline]
pub fn fsconfig_cmd_create_excl(fd: impl AsFd) -> Result<(), SyscallError> {
    //SAFETY: invariants on the provided types ensure this is a valid syscall
    let _ = unsafe {
        syscall5(
            abi::FSCONFIG,
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

/// `fsmount(2)`.
#[inline]
pub fn fsmount(
    fsfd: impl AsFd,
    flags: ffi::c_uint,
    attr_flags: ffi::c_uint,
) -> Result<OwnedFd, SyscallError> {
    //SAFETY: invariants on the provided types ensure this is a valid syscall
    let raw_fd = unsafe {
        syscall3(
            abi::FSMOUNT,
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
#[inline]
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
            abi::MOVE_MOUNT,
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
#[inline]
pub fn update_mount_propagation_flags(
    target: &CStr,
    mountflags: ffi::c_ulong,
) -> Result<(), SyscallError> {
    //SAFETY: invariants on the provided types ensure this is a valid syscall
    let _ = unsafe {
        syscall5(
            abi::MOUNT,
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
#[inline]
pub fn umount2(target: &CStr, flags: ffi::c_int) -> Result<(), SyscallError> {
    //SAFETY: invariants on the provided types ensure this is a valid syscall
    let _ = unsafe {
        syscall2(abi::UMOUNT2, Arg::from_c_str(target), Arg::from_int(flags))
            .wrap_syscall(Syscall::Umount2)?
    };

    Ok(())
}

/// `write(2)`.
#[inline]
pub fn write(fd: impl AsFd, buffer: &[u8]) -> Result<usize, SyscallError> {
    //SAFETY: invariants on the provided types ensure this is a valid syscall
    let n_written = unsafe {
        syscall3(
            abi::WRITE,
            Arg::from_fd(fd.as_fd()),
            Arg::from_ptr(buffer.as_ptr()),
            Arg::from_usize(buffer.len()),
        )
        .wrap_syscall(Syscall::Write)?
    };

    Ok(n_written as usize)
}

/// `read(2)`.
#[inline]
pub fn read(fd: impl AsFd, buffer: &mut [u8]) -> Result<usize, SyscallError> {
    let n_read = unsafe {
        syscall3(
            abi::READ,
            Arg::from_fd(fd.as_fd()),
            Arg::from_mut_ptr(buffer.as_mut_ptr()),
            Arg::from_usize(buffer.len()),
        )
        .wrap_syscall(Syscall::Read)?
    };

    Ok(n_read as usize)
}

/// `read(2)` wrapper that accepts [`MaybeUninit`] slices.
#[inline]
pub fn read_uninit(
    fd: impl AsFd,
    buffer: &mut [MaybeUninit<u8>],
) -> Result<usize, SyscallError> {
    let n_read = unsafe {
        syscall3(
            abi::READ,
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
#[inline]
pub unsafe fn close(fd: impl IntoRawFd) {
    //NOTE: i debated whether or not to take [`IntoRawFd`] as it does not
    //      strictly require ownership transfer, but the only
    //      alternative---taking [`RawFd`]---does not either. this is marginally
    //      more ergonomic anyway

    //NOTE: we intentionally ignore the error because the potential errors are
    //      more hazardous to handle than they are to ignore
    //SAFETY: the caller asserts this file descriptor is not expected to be
    //         open after this call
    let _ = unsafe { syscall1(abi::CLOSE, Arg::from_int(fd.into_raw_fd())) };
}

/// `eventfd2(2)`.
#[inline]
pub fn eventfd2(
    initval: ffi::c_uint,
    flags: ffi::c_int,
) -> Result<OwnedFd, SyscallError> {
    //SAFETY: there's no possible set of values here that would cause memory
    //        unsafety
    let raw_fd = unsafe {
        syscall2(abi::EVENTFD2, Arg::from_uint(initval), Arg::from_int(flags))
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
    #[inline]
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
    #[inline]
    pub fn revents(&self) -> ffi::c_short {
        self.0.revents
    }

    /// Clear the revents set by the kernel.
    #[inline]
    pub fn clear_revents(&mut self) {
        self.0.revents = 0;
    }
}

/// `ppoll(2)`.
#[inline]
pub fn ppoll(
    fds: &mut [PollFd<'_>],
    mut timeout: Option<impl BorrowMut<linux::__kernel_timespec>>,
) -> Result<usize, SyscallError> {
    let timespec = if let Some(timeout) = &mut timeout {
        timeout.borrow_mut()
    } else {
        ptr::null_mut::<linux::__kernel_timespec>()
    };

    //SAFETY: the invariants on all input types guarantee the safety of this
    let n_updated = unsafe {
        syscall5(
            abi::PPOLL,
            Arg::from_mut_ptr(fds.as_mut_ptr()),
            Arg::from_usize(fds.len()),
            Arg::from_mut_ptr(timespec),
            Arg::from_ptr(ptr::null::<linux::kernel_sigset_t>()),
            Arg::from_usize(size_of::<linux::kernel_sigset_t>()),
        )
        .wrap_syscall(Syscall::Ppoll)?
    };

    Ok(n_updated as usize)
}

/// `sethostname(2)`.
#[inline]
pub fn sethostname(name: &[u8]) -> Result<(), SyscallError> {
    //SAFETY: the invariants on all input types guarantee the safety of this
    let _ = unsafe {
        syscall2(
            abi::SETHOSTNAME,
            Arg::from_ptr(name.as_ptr()),
            Arg::from_usize(name.len()),
        )
        .wrap_syscall(Syscall::Sethostname)?
    };

    Ok(())
}

/// `setdomainname(2)`.
#[inline]
pub fn setdomainname(name: &[u8]) -> Result<(), SyscallError> {
    //SAFETY: the invariants on all input types guarantee the safety of this
    let _ = unsafe {
        syscall2(
            abi::SETDOMAINNAME,
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
#[inline]
pub fn raise_capability_into_ambient_set(
    cap: ffi::c_long,
) -> Result<(), SyscallError> {
    //SAFETY: there's not really an unsafe way to call this
    let _ = unsafe {
        syscall5(
            abi::PRCTL,
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
#[inline]
pub fn drop_capability_from_bounding_set(
    cap: ffi::c_long,
) -> Result<(), SyscallError> {
    //SAFETY: there's not really an unsafe way to call this
    let _ = unsafe {
        syscall5(
            abi::PRCTL,
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

/// `prctl(2)` with `PR_SET_NO_NEW_PRIVS(2const)`.
#[inline]
pub fn set_no_new_privs() -> Result<(), SyscallError> {
    //SAFETY: all parameters are constant and structurally correct
    let _ = unsafe {
        syscall5(
            abi::PRCTL,
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

/// `prctl(2)` with `PR_SET_PDEATHSIG(2const)`.
///
/// Provide zero as the signal to clear the death signal.
#[inline]
pub fn set_parent_thread_death_signal(
    sig: ffi::c_int,
) -> Result<(), SyscallError> {
    //SAFETY: all parameters are constant and structurally correct
    let _ = unsafe {
        syscall5(
            abi::PRCTL,
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

/// `capset(2)`.
#[inline]
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
            abi::CAPSET,
            Arg::from_ptr(&hdr),
            Arg::from_ptr(data.as_ptr()),
        )
        .wrap_syscall(Syscall::Capset)?
    };

    Ok(())
}

/// `setns(2)`.
#[inline]
pub fn setns(fd: impl AsFd, nstype: ffi::c_int) -> Result<(), SyscallError> {
    //SAFETY: safety is ensured by the types of the arguments provided
    //
    //        this syscall does not allow unsharing the file descriptor table,
    //        so there are no safety hazards posed by it
    let _ = unsafe {
        syscall2(abi::SETNS, Arg::from_fd(fd.as_fd()), Arg::from_int(nstype))
            .wrap_syscall(Syscall::Setns)?
    };

    Ok(())
}

/// `unshare(2)`.
///
/// # Safety
///
/// Refer to the manpage for information on the potential hazards with making
/// this syscall. There is too much to detail here.
#[inline]
pub unsafe fn unshare(flags: ffi::c_int) -> Result<(), SyscallError> {
    //SAFETY: the caller asserts that if they are using `CLONE_FILES` that this
    //        thread will not attempt to use file descriptors from other threads
    let _ = unsafe {
        syscall1(abi::UNSHARE, Arg::from_int(flags))
            .wrap_syscall(Syscall::Unshare)?
    };

    Ok(())
}

/// `chdir(2)`.
#[inline]
pub fn chdir(path: &CStr) -> Result<(), SyscallError> {
    //SAFETY: the type of the argument ensures this call is safe
    let _ = unsafe {
        syscall1(abi::CHDIR, Arg::from_c_str(path))
            .wrap_syscall(Syscall::Chdir)?
    };

    Ok(())
}

/// `fchdir(2)`.
#[inline]
pub fn fchdir(fd: impl AsFd) -> Result<(), SyscallError> {
    //SAFETY: the type of the argument ensures this call is safe
    let _ = unsafe {
        syscall1(abi::FCHDIR, Arg::from_fd(fd.as_fd()))
            .wrap_syscall(Syscall::Fchdir)?
    };

    Ok(())
}

/// `chroot(2)`.
#[inline]
pub fn chroot(path: &CStr) -> Result<(), SyscallError> {
    //SAFETY: the type of the argument ensures this call is safe
    let _ = unsafe {
        syscall1(abi::CHROOT, Arg::from_c_str(path))
            .wrap_syscall(Syscall::Chroot)?
    };

    Ok(())
}

/// `getegid(2)`.
#[inline]
pub fn getegid() -> Result<Gid, SyscallError> {
    //SAFETY: there are no arguments to pass from the user
    let raw_gid =
        unsafe { syscall0(abi::GETEGID).wrap_syscall(Syscall::Getegid)? };

    //SAFETY: this syscall won't return the maximum value
    Ok(unsafe { Gid::from_raw_unchecked(raw_gid as _) })
}

/// `geteuid(2)`.
#[inline]
pub fn geteuid() -> Result<Uid, SyscallError> {
    //SAFETY: there are no arguments to pass from the user
    let raw_uid =
        unsafe { syscall0(abi::GETEUID).wrap_syscall(Syscall::Geteuid)? };

    //SAFETY: this syscall won't return the maximum value
    Ok(unsafe { Uid::from_raw_unchecked(raw_uid as _) })
}

/// `gettid(2)`.
#[inline]
pub fn gettid() -> Result<Pid, SyscallError> {
    //SAFETY: there are no arguments to pass from the user
    let raw_tid =
        unsafe { syscall0(abi::GETTID).wrap_syscall(Syscall::Gettid)? };

    //SAFETY: `gettid(2)` returns a valid pid
    Ok(unsafe { Pid::from_raw_unchecked(raw_tid as _) })
}

/// `pidfd_open(2)`.
#[inline]
pub fn pidfd_open(
    pid: Pid,
    flags: ffi::c_uint,
) -> Result<OwnedFd, SyscallError> {
    //SAFETY: invariants upon the types ensure the call is valid
    let raw_fd = unsafe {
        syscall2(abi::PIDFD_OPEN, Arg::from_pid(pid), Arg::from_uint(flags))
            .wrap_syscall(Syscall::PidfdOpen)?
    };

    //SAFETY: `pidfd_open(2)` always returns a valid fd if it succeeds
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd as _) })
}

/// `pidfd_send_signal(2)` without `siginfo_t`.
#[inline]
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
            abi::PIDFD_SEND_SIGNAL,
            Arg::from_fd(pidfd.as_fd()),
            Arg::from_int(sig),
            Arg::from_ptr(ptr::null::<linux::siginfo_t>()),
            Arg::from_uint(flags),
        )
        .wrap_syscall(Syscall::PidfdSendSignal)?
    };

    Ok(())
}

/// `setsid(2)`.
#[inline]
pub fn setsid() -> Result<Pid, SyscallError> {
    //SAFETY: the caller passes no arguments to this function and this syscall
    //        cannot do anything that would cause memory unsafety
    let raw_pid =
        unsafe { syscall0(abi::SETSID).wrap_syscall(Syscall::Setsid)? };

    //SAFETY: `setsid(2)` always returns a valid pid
    Ok(unsafe { Pid::from_raw_unchecked(raw_pid as _) })
}

/// The target of a `waitid(2)` call.
#[derive(Copy, Clone, Debug)]
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
//TODO: allow the user to get information out of this. we don't really need it,
//      but we may in the future
#[allow(missing_debug_implementations)]
#[derive(Copy, Clone)]
pub struct WaitIdStatus(linux::siginfo_t);

/// `waitid(2)`.
#[inline]
pub fn waitid(
    target: WaitFor<'_>,
    options: ffi::c_int,
) -> Result<Option<WaitIdStatus>, SyscallError> {
    //TODO: consider supporting rusage. may need abi-dependent work---check

    //SAFETY: this is a c structure which is valid when initialized to zero.
    //        we also need this to distinguish the state w/ `WNOHANG` specified
    let mut info = unsafe { mem::zeroed::<linux::siginfo_t>() };

    let _ = match target {
        //TODO: consider breaking these out into their own functions?
        WaitFor::Pid(pid) => {
            //SAFETY: the types of arguments provided ensure the safety of this
            //        call
            unsafe {
                syscall5(
                    abi::WAITID,
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
                    abi::WAITID,
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
                    abi::WAITID,
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
                    abi::WAITID,
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
                    abi::WAITID,
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
#[inline]
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
        bytemuck::must_cast_slice_mut(target_ifname).copy_from_slice(ifname);
    } else {
        return Err(SyscallError::new(Syscall::Ioctl, Errno::INVAL));
    }

    //SAFETY: all arguments are guaranteed to be valid
    let _ = unsafe {
        syscall3(
            abi::IOCTL,
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
            abi::SOCKET,
            Arg::from_int(domain),
            Arg::from_int(kind),
            Arg::from_int(protocol),
        )
        .wrap_syscall(Syscall::Socket)?
    };

    //SAFETY: `socket(2)` returns a valid file descriptor on success
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd as _) })
}

/// `recvmsg(2)`.
//TODO: add extended support for this function, i.e. ancillary data, flags,
//      etc. currently this only has the bare minimum required to support our
//      netlink use case
#[inline]
pub fn recvmsg(
    sockfd: impl AsFd,
    buffer: &mut [u8],
    flags: ffi::c_int,
    msg_flags: &mut ffi::c_uint,
) -> Result<usize, SyscallError> {
    let mut iovec = linux::iovec {
        iov_base: buffer.as_mut_ptr().cast::<ffi::c_void>(),
        iov_len: buffer.len() as u64,
    };
    let iovec_mut: *mut linux::iovec = &mut iovec;

    let mut msghdr = linux_net::msghdr {
        msg_name: ptr::null_mut::<ffi::c_void>(),
        msg_namelen: 0,
        msg_iov: iovec_mut.cast::<linux_net::iovec>(),
        msg_iovlen: 1,
        msg_control: ptr::null_mut::<ffi::c_void>(),
        msg_controllen: 0,
        msg_flags: 0,
    };

    //SAFETY: the invariants of the provided types ensure this call is safe
    let n_read = unsafe {
        syscall3(
            abi::RECVMSG,
            Arg::from_fd(sockfd.as_fd()),
            Arg::from_mut_ptr(&mut msghdr),
            Arg::from_int(flags),
        )
        .wrap_syscall(Syscall::Recvmsg)?
    };

    //FIXME: get a better solution for passing these back
    *msg_flags = msghdr.msg_flags;
    Ok(n_read as _)
}

/// `sendto(2)` specialized for sending a netlink message to the kernel.
#[inline]
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
            abi::SENDTO,
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
#[inline]
pub fn exit(status: ffi::c_int) -> ! {
    let _ = unsafe { syscall1(abi::EXIT_GROUP, Arg::from_int(status)) };
    let _ = unsafe { syscall1(abi::EXIT, Arg::from_int(status)) };

    //NOTE: there is really no point to doing anything else here. the safest
    //      thing to do is just do a spin loop
    loop {
        hint::spin_loop();
    }
}

/// `close_range(2)`.
///
/// # Safety
///
/// It is the caller's responsibility to ensure that the specified file
/// descriptors are not expected to be open if called without
/// `CLOSE_RANGE_CLOEXEC`.
#[inline]
pub unsafe fn close_range(
    first: ffi::c_uint,
    last: ffi::c_uint,
    flags: ffi::c_int,
) -> Result<(), SyscallError> {
    //SAFETY: the caller has asserted these file descriptors are not used or we
    //        are only applying the close-on-exec flag.
    let _ = unsafe {
        syscall3(
            abi::CLOSE_RANGE,
            Arg::from_uint(first),
            Arg::from_uint(last),
            Arg::from_int(flags),
        )
        .wrap_syscall(Syscall::CloseRange)?
    };

    Ok(())
}

/// `execveat(2)`.
///
/// # Safety
///
/// `argv` and `envp` must be null-terminated arrays, as specified in
/// `execveat(2)`. Pointers to arguments and environment variables must be valid
/// C strings.
#[inline]
pub unsafe fn execveat<'a>(
    dirfd: impl Into<AtFd<'a>>,
    path: &CStr,
    argv: impl AsRef<[*const ffi::c_char]>,
    envp: impl AsRef<[*const ffi::c_char]>,
    flags: ffi::c_int,
) -> Result<!, SyscallError> {
    //SAFETY: caller has asserted `argv` and `envp` are valid
    let _ = unsafe {
        syscall5(
            abi::EXECVEAT,
            Arg::from_at_fd(&dirfd.into()),
            Arg::from_c_str(path),
            Arg::from_ptr(argv.as_ref().as_ptr()),
            Arg::from_ptr(envp.as_ref().as_ptr()),
            Arg::from_int(flags),
        )
        .wrap_syscall(Syscall::Execveat)?
    };

    unreachable!()
}

/// `rt_sigaction(2)`.
///
/// # Safety
///
/// Don't do this if you intend to do a write operation and are in a state where
/// a process runtime may care about that.
#[inline]
pub unsafe fn rt_sigaction(
    signum: ffi::c_int,
    act: Option<&linux::kernel_sigaction>,
    oldact: Option<&mut linux::kernel_sigaction>,
    sigsetsize: ffi::c_size_t,
) -> Result<(), SyscallError> {
    //SAFETY: caller has asserted they know a process runtime won't care about
    //        this.
    let _ = unsafe {
        syscall4(
            abi::RT_SIGACTION,
            Arg::from_int(signum),
            Arg::from_optional_ptr(act),
            Arg::from_optional_mut_ptr(oldact),
            Arg::from_size_t(sigsetsize),
        )
        .wrap_syscall(Syscall::RtSigaction)?
    };

    Ok(())
}

/// `rt_sigprocmask(2)`.
///
/// # Safety
///
/// Don't do this if you intend to do a write operation and are in a state where
/// a process runtime may care about that.
#[inline]
pub unsafe fn rt_sigprocmask(
    how: ffi::c_int,
    set: Option<&linux::kernel_sigset_t>,
    oldset: Option<&mut linux::kernel_sigset_t>,
    sigsetsize: ffi::c_size_t,
) -> Result<(), SyscallError> {
    //SAFETY: caller has asserted they know a process runtime won't care about
    //        this
    let _ = unsafe {
        syscall4(
            abi::RT_SIGPROCMASK,
            Arg::from_int(how),
            Arg::from_optional_ptr(set),
            Arg::from_optional_mut_ptr(oldset),
            Arg::from_size_t(sigsetsize),
        )
        .wrap_syscall(Syscall::RtSigprocmask)?
    };

    Ok(())
}

/// `ioctl(2)` on a pidfd to retrieve information about the process.
#[inline]
pub fn pidfd_get_info(fd: impl AsFd) -> Result<PidfdInfoV0, SyscallError> {
    let mut out = PidfdInfoV0::default();

    //NOTE: we don't need to set any of the other ones as the kernel returns
    //      them regardless of the mask
    out.mask = PIDFD_INFO_EXIT;

    //SAFETY: `out` is valid, `fd` is a valid fd by it implementing [`AsFd`].
    let _ = unsafe {
        syscall3(
            abi::IOCTL,
            Arg::from_fd(fd.as_fd()),
            Arg::from_ulong(PIDFD_GET_INFO_V0 as _),
            Arg::from_mut_ptr(&mut out),
        )
        .wrap_syscall(Syscall::Ioctl)?
    };

    Ok(out)
}

/// `symlinkat(2)`.
#[inline]
pub fn symlinkat<'a>(
    target: &CStr,
    newdirfd: impl Into<AtFd<'a>>,
    linkpath: &CStr,
) -> Result<(), SyscallError> {
    //SAFETY: incorrect flags have no bearing on the safety of this call.
    //        invariants upon the argument types (fd validity, reference
    //        validity) ensure memory safety
    let _ = unsafe {
        syscall3(
            abi::SYMLINKAT,
            Arg::from_c_str(target),
            Arg::from_at_fd(&newdirfd.into()),
            Arg::from_c_str(linkpath),
        )
        .wrap_syscall(Syscall::Symlinkat)?
    };

    Ok(())
}

/// `fcntl(2)` with `F_DUPFD_CLOEXEC(2const)`.
#[inline]
pub fn fcntl_dupfd_cloexec(oldfd: impl AsFd) -> Result<OwnedFd, SyscallError> {
    //SAFETY: we know this file descriptor is valid
    let newfd = unsafe {
        syscall3(
            abi::FCNTL,
            Arg::from_fd(oldfd.as_fd()),
            Arg::from_int(linux::F_DUPFD_CLOEXEC as ffi::c_int),
            Arg::from_int(0),
        )
        .wrap_syscall(Syscall::Fcntl)?
    };

    //SAFETY: we know this is valid by the syscall having not errored
    Ok(unsafe { OwnedFd::from_raw_fd(newfd as ffi::c_int) })
}
