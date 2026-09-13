// SPDX-License-Identifier: AGPL-3.0-only

//! Wrappers over IDs used by the kernel for processes, users, and groups.

use core::{
    fmt,
    hash::{Hash, Hasher},
    mem, pattern_type,
};
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
        debug_assert!(value != RawUid::MAX, "a user id must not be `-1`");

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
        debug_assert!(value != RawGid::MAX, "a group id must not be `-1`");

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

/// Wrapper over a positive process ID.
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct Pid(pattern_type!(RawPid is 1..));

impl fmt::Debug for Pid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Pid").field(&self.into_raw()).finish()
    }
}

impl PartialEq for Pid {
    fn eq(&self, other: &Pid) -> bool {
        self.into_raw() == other.into_raw()
    }
}

impl Eq for Pid {}

impl Hash for Pid {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.into_raw().hash(state)
    }
}

impl Pid {
    /// Access the raw process ID value.
    #[inline]
    pub const fn into_raw(self) -> RawPid {
        //SAFETY: valid pattern type values are equivalent to their base type
        unsafe { mem::transmute(self) }
    }

    /// Construct a process ID without checking the invariants.
    ///
    /// # Safety
    ///
    /// The value must be greater than zero.
    #[inline]
    pub const unsafe fn from_raw_unchecked(value: RawPid) -> Self {
        debug_assert!(value.is_positive(), "a pid must be greater than zero");

        //SAFETY: caller asserts value is in the specified range
        unsafe { mem::transmute(value) }
    }

    /// Construct a process ID, checking that it is greater than zero.
    #[inline]
    pub const fn from_raw(value: RawPid) -> Option<Self> {
        if let 1.. = value {
            //SAFETY: we just checked it is in the range
            Some(unsafe { Self::from_raw_unchecked(value) })
        } else {
            None
        }
    }
}
