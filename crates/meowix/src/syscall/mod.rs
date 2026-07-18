// SPDX-License-Identifier: AGPL-3.0-only

//! Tools for making direct syscalls in Rust code.

use core::{
    ffi::{self, CStr},
    ptr,
};
use linux_raw_sys::general as linux;

use crate::{
    fd::{AsFd, AsRawFd, BorrowedFd},
    ids::Pid,
    util::{AtFd, AtFdInner},
};

cfg_select! {
    all(target_arch = "x86_64", target_pointer_width = "64") => {
        mod x86_64;
        pub use x86_64::*;
    }
    _ => {
        mod generic;
        pub use generic::*;
    }
}

/// Representation of a syscall argument used for conversions.
#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct Arg(ffi::c_long);

impl Arg {
    /// Conversion to satisfy the syscall calling convention.
    #[inline(always)]
    pub fn into_raw(self) -> ffi::c_long {
        self.0
    }

    /// Construct a syscall argument from an immutable pointer value.
    #[inline(always)]
    pub fn from_ptr<T>(ptr: *const T) -> Self {
        Self(ptr as usize as ffi::c_long)
    }

    /// Construct a syscall argument from an optional immutable reference value
    #[inline(always)]
    pub fn from_optional_ptr<T>(ptr: Option<&T>) -> Self {
        Self::from_ptr(if let Some(ptr) = ptr {
            ptr
        } else {
            ptr::null::<T>()
        })
    }

    /// Construct a syscall argument from a mutable pointer value.
    #[inline(always)]
    pub fn from_mut_ptr<T>(ptr: *mut T) -> Self {
        Self(ptr as usize as ffi::c_long)
    }

    /// Construct a syscall argument from an optional mutable reference value
    #[inline(always)]
    pub fn from_optional_mut_ptr<T>(ptr: Option<&mut T>) -> Self {
        Self::from_mut_ptr(if let Some(ptr) = ptr {
            ptr
        } else {
            ptr::null_mut::<T>()
        })
    }

    /// Construct a syscall argument from a C string.
    #[inline(always)]
    pub fn from_c_str(c_str: &'_ CStr) -> Self {
        Self::from_ptr(c_str.as_ptr())
    }

    /// Construct a syscall argument from a file descriptor.
    #[inline(always)]
    pub fn from_fd(fd: BorrowedFd<'_>) -> Self {
        Self(fd.as_fd().as_raw_fd() as ffi::c_long)
    }

    /// Construct a syscall argument from an [`AtFd`].
    ///
    /// We can't take it directly as that would drop an owned file descriptor if
    /// it is.
    #[inline(always)]
    pub fn from_at_fd(fd: &AtFd<'_>) -> Self {
        match fd.inner {
            AtFdInner::Borrowed(fd) => Self::from_fd(fd.as_fd()),
            AtFdInner::Owned(ref fd) => Self::from_fd(fd.as_fd()),
            AtFdInner::Cwd => Self::from_int(linux::AT_FDCWD),
        }
    }

    /// Construct a syscall argument from an unsigned integer.
    #[inline(always)]
    pub fn from_uint(value: ffi::c_uint) -> Self {
        Self(value as ffi::c_long)
    }

    /// Construct a syscall argument from a signed integer.
    #[inline(always)]
    pub fn from_int(value: ffi::c_int) -> Self {
        Self(value as ffi::c_long)
    }

    /// Construct a syscall argument from an unsigned long.
    #[inline(always)]
    pub fn from_ulong(value: ffi::c_ulong) -> Self {
        Self(value as ffi::c_long)
    }

    /// Construct a syscall from a signed long.
    #[inline(always)]
    pub fn from_long(value: ffi::c_long) -> Self {
        Self(value)
    }

    /// Construct a syscall argument from a usize value.
    #[inline(always)]
    pub fn from_usize(value: usize) -> Self {
        Self(value as ffi::c_long)
    }

    /// Construct a syscall argument from a size_t value.
    #[inline(always)]
    pub fn from_size_t(value: ffi::c_size_t) -> Self {
        Self(value as ffi::c_ulong as ffi::c_long)
    }

    /// Construct a syscall argument from a pid.
    #[inline(always)]
    pub fn from_pid(pid: Pid) -> Self {
        Self::from_int(pid.into_raw())
    }
}
