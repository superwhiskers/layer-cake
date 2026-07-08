// SPDX-License-Identifier: AGPL-3.0-only

//! Linux capabilities.

use linux_raw_sys::general as linux;

use super::{errno::Errno, errors::SyscallError, syscalls};

/// Exclusive upper bound on the bit offset of a represented capability in a
/// [`CapabilitySet`].
const MAX_LAST_CAP: u64 = u64::BITS as u64;

/// Drop capabilities from the bounding set of the process other than those
/// specified.
///
/// # Errors
///
/// This function errors if `PR_CAPBSET_DROP(2const)` fails with an error
/// other than `EINVAL`.
pub fn drop_bounding_set(
    other_than: CapabilitySet,
) -> Result<(), SyscallError> {
    for cap in 0..MAX_LAST_CAP {
        if other_than.contains(CapabilitySet::from_bits_retain(1_u64 << cap)) {
            continue;
        }

        if let Err(e) = syscalls::drop_capability_from_bounding_set(cap as _)
            //NOTE: einval implies the capability was not known to the kernel
            && !matches!(e.error(), Errno::INVAL)
        {
            return Err(e);
        }
    }
    Ok(())
}

/// Raise the specified capabilities into the ambient set of the process.
///
/// # Errors
///
/// This function errors if `PR_CAP_AMBIENT(2const)` fails with an error other
/// than `EINVAL`.
pub fn set_ambient_capabilities(
    raise: CapabilitySet,
) -> Result<(), SyscallError> {
    for cap in 0..MAX_LAST_CAP {
        if raise.contains(CapabilitySet::from_bits_retain(1_u64 << cap))
            && let Err(e) =
                //NOTE: more c type messiness
                syscalls::raise_capability_into_ambient_set(cap as _)
            && !matches!(e.error(), Errno::INVAL)
        {
            return Err(e);
        }
    }
    Ok(())
}

/// Wrapper for [`linux::cap_user_data_t`] that supports splitting the
/// capability set into low and high bits.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CapabilitySets {
    /// Effective capability set.
    pub effective: CapabilitySet,

    /// Permitted capability set.
    pub permitted: CapabilitySet,

    /// Inheritable capability set.
    pub inheritable: CapabilitySet,
}

impl CapabilitySets {
    /// Convert this capability set structure into
    /// [`linux::__user_cap_data_struct`]s for the low and high capability bits.
    #[inline]
    pub fn into_user_cap_data_struct(
        self,
    ) -> [linux::__user_cap_data_struct; 2] {
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

bitflags::bitflags! {
    /// Linux `CAP_*` constants.
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
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
    }
}
