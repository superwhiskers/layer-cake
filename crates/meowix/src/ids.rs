// SPDX-License-Identifier: AGPL-3.0-only

//! Wrappers over IDs used by the kernel for processes, users, and groups.

use core::num::NonZero;
use linux_raw_sys::general as linux;

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
    #[inline]
    pub const fn into_raw(self) -> RawUid {
        self.0
    }

    /// Construct a user ID without checking for `-1`.
    ///
    /// # Safety
    ///
    /// This value must not be `-1`.
    #[inline]
    pub const unsafe fn from_raw_unchecked(value: RawUid) -> Self {
        Self(value)
    }

    /// Construct a user ID, checking for `-1`.
    #[inline]
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
    #[inline]
    pub const fn into_raw(self) -> RawGid {
        self.0
    }

    /// Construct a group ID without checking for `-1`.
    ///
    /// # Safety
    ///
    /// This value must not be `-1`.
    #[inline]
    pub const unsafe fn from_raw_unchecked(value: RawGid) -> Self {
        Self(value)
    }

    /// Construct a group ID, checking for `-1`.
    #[inline]
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
    #[inline]
    pub const fn into_raw(self) -> RawPid {
        self.0.get()
    }

    /// Access the raw process ID value as a nonzero value.
    #[inline]
    pub const fn into_raw_nonzero(self) -> NonZero<RawPid> {
        self.0
    }

    /// Construct a process ID without checking that it is nonzero.
    ///
    /// # Safety
    ///
    /// The value must not be zero.
    #[inline]
    pub const unsafe fn from_raw_unchecked(value: RawPid) -> Self {
        //SAFETY: caller has asserted the correctness of this
        Self(unsafe { NonZero::<RawPid>::new_unchecked(value) })
    }

    /// Construct a process ID from a nonzero value.
    #[inline]
    pub const fn from_raw_nonzero(value: NonZero<RawPid>) -> Self {
        Self(value)
    }

    /// Construct a process ID, checking that it is not zero.
    #[inline]
    pub const fn from_raw(value: RawPid) -> Option<Self> {
        if let Some(value) = NonZero::<RawPid>::new(value) {
            Some(Self(value))
        } else {
            None
        }
    }
}
