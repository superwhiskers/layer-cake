// SPDX-License-Identifier: AGPL-3.0-only

//! Syscall constants for the target architecture.
//!
//! This module is used to conditionally select syscalls based on the target
//! architecture, when this is necessary.
//!
//! Currently, this is used to select `__NR_ppoll_time64`, `__NR_geteuid32`, and
//! `__NR_getegid32` over their older equivalents on 32-bit width pointer
//! architectures.

use core::ffi;
use linux_raw_sys::general as linux;

pub const CLONE3: ffi::c_long = linux::__NR_clone3 as _;
pub const MOUNT_SETATTR: ffi::c_long = linux::__NR_mount_setattr as _;
pub const DUP3: ffi::c_long = linux::__NR_dup3 as _;
pub const OPEN_TREE_ATTR: ffi::c_long = linux::__NR_open_tree_attr as _;
pub const OPEN_TREE: ffi::c_long = linux::__NR_open_tree as _;
pub const PIPE2: ffi::c_long = linux::__NR_pipe2 as _;
pub const OPENAT2: ffi::c_long = linux::__NR_openat2 as _;
pub const MKDIRAT: ffi::c_long = linux::__NR_mkdirat as _;
pub const UMASK: ffi::c_long = linux::__NR_umask as _;
pub const STATX: ffi::c_long = linux::__NR_statx as _;
pub const FSOPEN: ffi::c_long = linux::__NR_fsopen as _;
pub const FSCONFIG: ffi::c_long = linux::__NR_fsconfig as _;
pub const FSMOUNT: ffi::c_long = linux::__NR_fsmount as _;
pub const MOVE_MOUNT: ffi::c_long = linux::__NR_move_mount as _;
pub const MOUNT: ffi::c_long = linux::__NR_mount as _;
pub const UMOUNT2: ffi::c_long = linux::__NR_umount2 as _;
pub const WRITE: ffi::c_long = linux::__NR_write as _;
pub const READ: ffi::c_long = linux::__NR_read as _;
pub const CLOSE: ffi::c_long = linux::__NR_close as _;
pub const EVENTFD2: ffi::c_long = linux::__NR_eventfd2 as _;
pub const SETHOSTNAME: ffi::c_long = linux::__NR_sethostname as _;
pub const SETDOMAINNAME: ffi::c_long = linux::__NR_setdomainname as _;
pub const PRCTL: ffi::c_long = linux::__NR_prctl as _;
pub const CAPSET: ffi::c_long = linux::__NR_capset as _;
pub const SETNS: ffi::c_long = linux::__NR_setns as _;
pub const UNSHARE: ffi::c_long = linux::__NR_unshare as _;
pub const CHDIR: ffi::c_long = linux::__NR_chdir as _;
pub const FCHDIR: ffi::c_long = linux::__NR_fchdir as _;
pub const CHROOT: ffi::c_long = linux::__NR_chroot as _;
pub const GETTID: ffi::c_long = linux::__NR_gettid as _;
pub const PIDFD_OPEN: ffi::c_long = linux::__NR_pidfd_open as _;
pub const PIDFD_SEND_SIGNAL: ffi::c_long = linux::__NR_pidfd_send_signal as _;
pub const SETSID: ffi::c_long = linux::__NR_setsid as _;
pub const WAITID: ffi::c_long = linux::__NR_waitid as _;
pub const IOCTL: ffi::c_long = linux::__NR_ioctl as _;
pub const SOCKET: ffi::c_long = linux::__NR_socket as _;
pub const RECVFROM: ffi::c_long = linux::__NR_recvfrom as _;
pub const SENDTO: ffi::c_long = linux::__NR_sendto as _;
pub const EXIT_GROUP: ffi::c_long = linux::__NR_exit_group as _;
pub const EXIT: ffi::c_long = linux::__NR_exit as _;
pub const CLOSE_RANGE: ffi::c_long = linux::__NR_close_range as _;
pub const EXECVEAT: ffi::c_long = linux::__NR_execveat as _;
pub const RT_SIGACTION: ffi::c_long = linux::__NR_rt_sigaction as _;
pub const RT_SIGPROCMASK: ffi::c_long = linux::__NR_rt_sigprocmask as _;
pub const SYMLINKAT: ffi::c_long = linux::__NR_symlinkat as _;

pub use architecture_specific::*;

#[cfg(target_pointer_width = "64")]
mod architecture_specific {
    use super::*;

    pub const PPOLL: ffi::c_long = linux::__NR_ppoll as _;
    pub const GETEUID: ffi::c_long = linux::__NR_geteuid as _;
    pub const GETEGID: ffi::c_long = linux::__NR_getegid as _;
}

#[cfg(target_pointer_width = "32")]
mod architecture_specific {
    use super::*;

    pub const PPOLL: ffi::c_long = linux::__NR_ppoll_time64 as _;
    pub const GETEUID: ffi::c_long = linux::__NR_geteuid32 as _;
    pub const GETEGID: ffi::c_long = linux::__NR_getegid32 as _;
}
