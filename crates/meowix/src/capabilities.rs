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

        if let Err(e) = syscalls::drop_capability_from_bounding_set(cap as _) {
            //NOTE: the capability space is contiguous so we can stop here
            if e.error() == Errno::INVAL {
                break;
            }
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
        {
            //NOTE: the capability space is contiguous so we can stop here
            if e.error() == Errno::INVAL {
                break;
            }
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

macro_rules! capabilities {
    ($(($name:ident, $constant:ident)),*) => {
        capabilities!(@structure $(($name, $constant)),*);

        impl CapabilitySet {
            /// Convert a string to a capability constant.
            pub fn from_str(value: impl AsRef<str>) -> Option<Self> {
                match value.as_ref() {
                    $(
                        stringify!($name) => Some(Self::$name),
                    )*
                    _ => None,
                }
            }
        }
    };
    (@structure $(($name:ident, $constant:ident)),*) => {
        bitflags::bitflags! {
            /// Linux `CAP_*` constants.
            #[repr(transparent)]
            #[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
            pub struct CapabilitySet: u64 {
                $(
                    /// `
                    #[doc = stringify!($constant)]
                    /// `.
                    const $name = 1 << linux::$constant;
                )*
            }
        }
    };
}

capabilities![
    (CHOWN, CAP_CHOWN),
    (DAC_OVERRIDE, CAP_DAC_OVERRIDE),
    (DAC_READ_SEARCH, CAP_DAC_READ_SEARCH),
    (FOWNER, CAP_FOWNER),
    (FSETID, CAP_FSETID),
    (KILL, CAP_KILL),
    (SETGID, CAP_SETGID),
    (SETUID, CAP_SETUID),
    (SETPCAP, CAP_SETPCAP),
    (LINUX_IMMUTABLE, CAP_LINUX_IMMUTABLE),
    (NET_BIND_SERVICE, CAP_NET_BIND_SERVICE),
    (NET_BROADCAST, CAP_NET_BROADCAST),
    (NET_ADMIN, CAP_NET_ADMIN),
    (NET_RAW, CAP_NET_RAW),
    (IPC_LOCK, CAP_IPC_LOCK),
    (IPC_OWNER, CAP_IPC_OWNER),
    (SYS_MODULE, CAP_SYS_MODULE),
    (SYS_RAWIO, CAP_SYS_RAWIO),
    (SYS_CHROOT, CAP_SYS_CHROOT),
    (SYS_PTRACE, CAP_SYS_PTRACE),
    (SYS_PACCT, CAP_SYS_PACCT),
    (SYS_ADMIN, CAP_SYS_ADMIN),
    (SYS_BOOT, CAP_SYS_BOOT),
    (SYS_NICE, CAP_SYS_NICE),
    (SYS_RESOURCE, CAP_SYS_RESOURCE),
    (SYS_TIME, CAP_SYS_TIME),
    (SYS_TTY_CONFIG, CAP_SYS_TTY_CONFIG),
    (MKNOD, CAP_MKNOD),
    (LEASE, CAP_LEASE),
    (AUDIT_WRITE, CAP_AUDIT_WRITE),
    (AUDIT_CONTROL, CAP_AUDIT_CONTROL),
    (SETFCAP, CAP_SETFCAP),
    (MAC_OVERRIDE, CAP_MAC_OVERRIDE),
    (MAC_ADMIN, CAP_MAC_ADMIN),
    (SYSLOG, CAP_SYSLOG),
    (WAKE_ALARM, CAP_WAKE_ALARM),
    (BLOCK_SUSPEND, CAP_BLOCK_SUSPEND),
    (AUDIT_READ, CAP_AUDIT_READ),
    (PERFMON, CAP_PERFMON),
    (BPF, CAP_BPF),
    (CHECKPOINT_RESTORE, CAP_CHECKPOINT_RESTORE)
];
